package sts;
import java.util.*;
public class Benchmark {
  public static void main(String[] args) throws Exception {
    int n = args.length>0?Integer.parseInt(args[0]):200_000;
    var gen=new Generator(42); var events=gen.mixed(n);
    // duplicate 1% to exercise dedup + burst queue for lag measurement
    var queue=new ArrayDeque<Event>(); int maxLag=0;
    var pipe=new Pipeline(); var sink=new Pipeline.MemorySink();
    long t0=System.nanoTime();
    // Simulate producer burst: enqueue all, consumer drains in chunks -> lag = queue depth sampled
    queue.addAll(events); maxLag=queue.size(); var drained=new ArrayList<Event>();
    while(!queue.isEmpty()){ for(int i=0;i<5000&&!queue.isEmpty();i++) drained.add(queue.poll()); }
    var res=pipe.run(drained,sink); double secs=(System.nanoTime()-t0)/1e9;
    // Precision/recall per attack type: incident summary contains type; truth = labeled users per type
    Map<String,Set<String>> truth=new HashMap<>(), pred=new HashMap<>();
    for(var e: events) if(e.attackType()!=null) truth.computeIfAbsent(e.attackType(),k->new HashSet<>()).add(e.user());
    for(var i: res.incidents()) for(String t: truth.keySet()) if(i.summary().contains(t)) pred.computeIfAbsent(t,k->new HashSet<>()).add(i.user());
    System.out.printf(Locale.ROOT,"events=%d processed=%d deduped=%d incidents=%d%n",events.size(),res.processed(),res.deduped(),res.incidents().size());
    System.out.printf(Locale.ROOT,"throughput_events_per_sec=%.0f%n",res.processed()/secs);
    System.out.printf(Locale.ROOT,"e2e_latency_p50_ms=%.3f p99_ms=%.3f (in-process per-event)%n",res.pct(0.50),res.pct(0.99));
    System.out.printf(Locale.ROOT,"consumer_lag_burst_max=%d drained_to=0%n",maxLag);
    for(String t: List.of("credential_stuffing","dns_tunneling","data_exfiltration","impossible_travel")){
      var tr=truth.getOrDefault(t,Set.of()); var pr=pred.getOrDefault(t,Set.of()); var tp=new HashSet<>(tr); tp.retainAll(pr);
      double prec=pr.isEmpty()?0:(double)tp.size()/pr.size(), rec=tr.isEmpty()?0:(double)tp.size()/tr.size();
      System.out.printf(Locale.ROOT,"detection[%s] precision=%.2f recall=%.2f (tp=%d pred=%d truth=%d)%n",t,prec,rec,tp.size(),pr.size(),tr.size());
    }
    if(args.length>1) java.nio.file.Files.writeString(java.nio.file.Path.of(args[1]), events.stream().map(Event::toJson).reduce("",(a,b)->a+b+"\n"));
  }
}
