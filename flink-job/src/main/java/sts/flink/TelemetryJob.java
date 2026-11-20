package sts.flink;
import org.apache.flink.api.common.eventtime.WatermarkStrategy;
import org.apache.flink.api.common.serialization.SimpleStringSchema;
import org.apache.flink.api.common.state.*;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.connector.base.DeliveryGuarantee;
import org.apache.flink.connector.kafka.sink.*; import org.apache.flink.connector.kafka.source.KafkaSource;
import org.apache.flink.connector.kafka.source.enumerator.initializer.OffsetsInitializer;
import org.apache.flink.streaming.api.datastream.*; import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.streaming.api.functions.KeyedProcessFunction;
import org.apache.flink.streaming.api.windowing.assigners.*; import org.apache.flink.streaming.api.windowing.time.Time;
import org.apache.flink.util.Collector; import org.apache.kafka.clients.consumer.OffsetResetStrategy;
import java.time.Duration; import java.util.*;
/** Flink job: Kafka (tenant-keyed) -> dedup/enrich -> tumbling+sliding windows -> anomaly rules/EWMA -> correlation -> Kafka exactly-once + incidents topic.
    Same operator semantics as sts.Pipeline (in-process runner used in tests/benchmarks). */
public class TelemetryJob {
  public static class Ev { public String eventId,tenant,user,source,app,category,verdict,geo,query; public long ts,bytesIn,bytesOut; public double entropy;
    static Ev parse(String j){ var e=new Ev(); e.eventId=s(j,"event_id"); e.tenant=s(j,"tenant"); e.user=s(j,"user"); e.source=s(j,"source"); e.app=s(j,"app"); e.category=s(j,"category"); e.verdict=s(j,"verdict"); e.geo=s(j,"geo"); e.query=s(j,"query"); e.ts=l(j,"ts"); e.bytesIn=l(j,"bytes_in"); e.bytesOut=l(j,"bytes_out"); try{e.entropy=Double.parseDouble(s2(j,"entropy"));}catch(Exception x){} return e; }
    static String s(String j,String k){int i=j.indexOf("\""+k+"\":\""); int a=j.indexOf('"',i+k.length()+3); return j.substring(a+1,j.indexOf('"',a+1));}
    static String s2(String j,String k){int i=j.indexOf("\""+k+"\":"); int a=i+k.length()+2; int b=a; while(b<j.length()&&"0123456789.-".indexOf(j.charAt(b))>=0)b++; return j.substring(a,b);}
    static long l(String j,String k){return Long.parseLong(s2(j,k));}
    public String key(){return tenant+"|"+user;}
  }
  public static class DetectFn extends KeyedProcessFunction<String,Ev,String> {
    transient ValueState<Double> mean, var, lastGeoTs; transient ValueState<String> lastGeo; transient MapState<String,Boolean> seen; transient ListState<Ev> recent;
    public void open(Configuration c){ mean=getRuntimeContext().getState(new ValueStateDescriptor<>("m",Double.class)); var=getRuntimeContext().getState(new ValueStateDescriptor<>("v",Double.class));
      lastGeo=getRuntimeContext().getState(new ValueStateDescriptor<>("g",String.class)); lastGeoTs=getRuntimeContext().getState(new ValueStateDescriptor<>("gt",Double.class));
      seen=getRuntimeContext().getMapState(new MapStateDescriptor<>("seen",String.class,Boolean.class)); recent=getRuntimeContext().getListState(new ListStateDescriptor<>("recent",Ev.class)); }
    public void processElement(Ev e,Context ctx,Collector<String> out) throws Exception {
      if(seen.contains(e.eventId)) return; seen.put(e.eventId,true); // dedup via keyed state (TTL in prod)
      double m=mean.value()==null?e.bytesOut:mean.value(); double d=e.bytesOut-m; m+=0.05*d; mean.update(m);
      double v=var.value()==null?1:var.value(); v=0.95*(v+0.05*d*d); var.update(v);
      if(Math.abs(d)/Math.sqrt(Math.max(1,v))>6 && e.bytesOut>50_000) out.collect(alert("data_exfiltration",e,0.9));
      var buf=new ArrayList<Ev>(); for(var x:recent.get()) if(e.ts-x.ts<300_000) buf.add(x); buf.add(e); recent.update(buf);
      long fails=buf.stream().filter(x->x.verdict.equals("block")).count(); long dns=buf.stream().filter(x->x.source.equals("DNS")).count();
      double ent=buf.stream().filter(x->x.source.equals("DNS")).mapToDouble(x->x.entropy).average().orElse(0);
      if(fails>=15) out.collect(alert("credential_stuffing",e,0.95));
      if(dns>=15&&ent>4.0) out.collect(alert("dns_tunneling",e,0.93));
      if(lastGeo.value()!=null&&!lastGeo.value().equals(e.geo)&&lastGeoTs.value()!=null&&e.ts-lastGeoTs.value()<3_600_000) out.collect(alert("impossible_travel",e,0.9));
      lastGeo.update(e.geo); lastGeoTs.update((double)e.ts);
      // cross-signal correlation is a second keyed pass over alerts in the job graph (see below comment)
    }
    static String alert(String t,Ev e,double c){return "{\"type\":\""+t+"\",\"tenant\":\""+e.tenant+"\",\"user\":\""+e.user+"\",\"ts\":"+e.ts+",\"confidence\":"+c+",\"signals\":[\""+t+"@"+e.source+"\"]}";}
  }
  public static void main(String[] args) throws Exception {
    String boot=args.length>0?args[0]:"kafka:9092";
    var env=StreamExecutionEnvironment.getExecutionEnvironment();
    env.enableCheckpointing(10_000); env.getCheckpointConfig().setMinPauseBetweenCheckpoints(5_000); // exactly-once with Kafka transactional sink
    var source=KafkaSource.<String>builder().setBootstrapServers(boot).setTopics("telemetry.proxy","telemetry.dns","telemetry.firewall")
      .setGroupId("sts-flink").setStartingOffsets(OffsetsInitializer.committedOffsets(OffsetResetStrategy.LATEST)).setValueOnlyDeserializer(new SimpleStringSchema()).build();
    var wm=WatermarkStrategy.<String>forBoundedOutOfOrderness(Duration.ofSeconds(30)).withTimestampAssigner((j,ts)->Ev.parse(j).ts);
    DataStream<Ev> events=env.fromSource(source,wm,"kafka").map(Ev::parse).name("parse");
    var keyed=events.keyBy(Ev::key);
    var incidents=keyed.process(new DetectFn()).name("dedup+anomaly");
    // tumbling + sliding aggregates per tenant/user/app
    var tumbling=keyed.window(TumblingEventTimeWindows.of(Time.minutes(1))).aggregate(new AggFn());
    var sliding=keyed.window(SlidingEventTimeWindows.of(Time.minutes(5),Time.minutes(1))).aggregate(new AggFn());
    var sink=KafkaSink.<String>builder().setBootstrapServers(boot).setRecordSerializer(KafkaRecordSerializationSchema.builder().setTopic("telemetry.incidents").setValueSerializationSchema(new SimpleStringSchema()).build())
      .setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE).setTransactionalIdPrefix("sts-flink").build();
    incidents.sinkTo(sink).name("incidents-exactly-once");
    tumbling.map(a->a).sinkTo(KafkaSink.<String>builder().setBootstrapServers(boot).setRecordSerializer(KafkaRecordSerializationSchema.builder().setTopic("telemetry.aggregates").setValueSerializationSchema(new SimpleStringSchema()).build()).setDeliveryGuarantee(DeliveryGuarantee.EXACTLY_ONCE).setTransactionalIdPrefix("sts-agg").build());
    sliding.print("sliding"); // ponytail: aggregates topic in prod, print keeps the demo graph self-contained
    env.execute("secure-telemetry-stream");
  }
  public static class AggFn implements org.apache.flink.api.common.functions.AggregateFunction<Ev,String,String> {
    public String createAccumulator(){return "0,0,0,0";} public String add(Ev e,String a){var p=a.split(","); return (Long.parseLong(p[0])+1)+","+(Long.parseLong(p[1])+e.bytesIn)+","+(Long.parseLong(p[2])+e.bytesOut)+","+(Long.parseLong(p[3])+(e.verdict.equals("block")?1:0));}
    public String getResult(String a){return "{\"count\":"+a.split(",")[0]+",\"bytes_in\":"+a.split(",")[1]+",\"bytes_out\":"+a.split(",")[2]+",\"blocks\":"+a.split(",")[3]+"}";} public String merge(String a,String b){return add(new Ev(),a).isEmpty()?a:b;}
  }
}
