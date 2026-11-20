package sts;
import java.io.*; import java.net.URI; import java.net.http.*; import java.nio.file.*; import java.util.*;
/** In-process runner of the same operators as the Flink job: dedup -> enrich -> windows -> detect -> correlate -> sink.
    ponytail: single-threaded sorted replay; Flink job (flink-job/) is the distributed version. */
public class Pipeline {
  public interface Sink { void event(Event e); void incident(Detectors.Incident i); }
  public static class MemorySink implements Sink { public final List<Event> events=new ArrayList<>(); public final List<Detectors.Incident> incidents=new ArrayList<>();
    public void event(Event e){events.add(e);} public void incident(Detectors.Incident i){incidents.add(i);} }
  /** ClickHouse over HTTP (JSONEachRow); falls back to a local JSONL file DuckDB can query (see store/duckdb.sql). */
  public static class ColumnarSink implements Sink { final Path file; final String chUrl; final HttpClient http=HttpClient.newHttpClient();
    public ColumnarSink(Path f,String chUrl){file=f;this.chUrl=chUrl;}
    public void event(Event e){ write(e.toJson()); } public void incident(Detectors.Incident i){ write("{\"user\":\""+i.user()+"\",\"tenant\":\""+i.tenant()+"\",\"ts\":"+i.ts()+",\"confidence\":"+i.confidence()+",\"summary\":\""+i.summary().replace("\"","")+"\"}"); }
    void write(String json){ try{ if(chUrl!=null&&!chUrl.isBlank()){ var req=HttpRequest.newBuilder(URI.create(chUrl+"/?query=INSERT%20INTO%20events%20FORMAT%20JSONEachRow")).POST(HttpRequest.BodyPublishers.ofString(json+"\n")).build(); var resp=http.send(req,HttpResponse.BodyHandlers.discarding()); if(resp.statusCode()<300) return; }
      Files.writeString(file,json+"\n",StandardOpenOption.CREATE,StandardOpenOption.APPEND); }catch(Exception ex){ throw new RuntimeException(ex);} }
  }
  public record Agg(String key,long windowStart,long count,long bytesIn,long bytesOut,long blocks){}
  public final Set<String> seen=new HashSet<>(); public final Map<String,Agg> tumbling=new HashMap<>(), sliding=new HashMap<>();
  public final Detectors.Detector detector=new Detectors.Detector(); public final Detectors.Correlator correlator=new Detectors.Correlator();
  public long deduped=0, processed=0; public final List<Long> latenciesNs=new ArrayList<>();
  public Result run(List<Event> input, Sink sink){
    var sorted=new ArrayList<>(input); sorted.sort(Comparator.comparingLong(Event::ts)); // event-time order; Flink uses watermarks for out-of-order
    var incidents=new ArrayList<Detectors.Incident>();
    for(Event e: sorted){ long t0=System.nanoTime();
      if(!seen.add(e.eventId())){deduped++; continue;}
      processed++; sink.event(e);
      agg(tumbling,e,60_000,0); agg(sliding,e,60_000,30_000);
      for(var a: detector.onEvent(e)) correlator.onAlert(a,e.source(),e.ts()).ifPresent(i->{incidents.add(i); sink.incident(i);});
      if(latenciesNs.size()<200_000) latenciesNs.add(System.nanoTime()-t0);
    }
    return new Result(processed,deduped,incidents,new ArrayList<>(tumbling.values()),latenciesNs);
  }
  static void agg(Map<String,Agg> m, Event e,long size,long slide){ long ws= slide==0? (e.ts()/size)*size : (e.ts()/size)*size; String k=e.tenant()+"|"+e.user()+"|"+e.app()+"|"+ws;
    m.merge(k,new Agg(k,ws,1,e.bytesIn(),e.bytesOut(),e.verdict().equals("block")?1:0),(a,b)->new Agg(k,ws,a.count()+1,a.bytesIn()+b.bytesIn(),a.bytesOut()+b.bytesOut(),a.blocks()+b.blocks())); }
  public record Result(long processed,long deduped,List<Detectors.Incident> incidents,List<Agg> aggregates,List<Long> latenciesNs){
    public double pct(double p){ if(latenciesNs.isEmpty())return 0; var s=new ArrayList<>(latenciesNs); Collections.sort(s); return s.get(Math.min(s.size()-1,(int)(p*s.size())))/1e6; }
  }
  /** Kafka partition key helper: tenant-partitioned topics. */
  public static int partitionFor(String tenant,int partitions){ return Math.floorMod(tenant.hashCode(),partitions); }
}
