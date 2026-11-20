package sts;
import java.util.*; import org.apache.kafka.clients.producer.*; import org.apache.kafka.common.serialization.StringSerializer;
/** `java sts.LoadGenerator [bootstrapServers|-] [count]` — Kafka topics telemetry.{proxy,dns,firewall}, key=tenant (tenant partitioning), JSON value. '-' prints JSONL. */
public class LoadGenerator {
  public static void main(String[] args){
    String boot=args.length>0?args[0]:"-"; int n=args.length>1?Integer.parseInt(args[1]):10_000; var ev=new Generator(7).mixed(n);
    if(boot.equals("-")){ for(var e: ev) System.out.println(e.tenant()+"\t"+e.toJson()); return; }
    var p=new Properties(); p.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG,boot); p.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG,StringSerializer.class); p.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG,StringSerializer.class);
    p.put(ProducerConfig.ACKS_CONFIG,"all"); p.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG,true); // backpressure: bounded buffer, block not drop
    p.put(ProducerConfig.MAX_BLOCK_MS_CONFIG,30_000); p.put(ProducerConfig.BUFFER_MEMORY_CONFIG,64*1024*1024); p.put(ProducerConfig.COMPRESSION_TYPE_CONFIG,"lz4");
    try(var prod=new KafkaProducer<String,String>(p)){ for(var e: ev) prod.send(new ProducerRecord<>("telemetry."+e.source().toLowerCase(),e.tenant(),e.toJson())); prod.flush(); }
  }
}
