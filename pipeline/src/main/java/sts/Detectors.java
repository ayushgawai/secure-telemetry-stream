package sts;
import java.util.*;
public class Detectors {
  public record Alert(String type,String key,String user,String tenant,long ts,double score,String detail){}
  public record Incident(String user,String tenant,long ts,double confidence,List<String> signals,String summary){}

  public static class Robust { // median/MAD robust z-score
    final List<Double> v=new ArrayList<>();
    public void add(double x){v.add(x); if(v.size()>500)v.remove(0);}
    public double z(double x){ if(v.size()<8) return 0; var s=new ArrayList<>(v); Collections.sort(s); double med=s.get(s.size()/2);
      List<Double> dev=new ArrayList<>(); for(double d:v)dev.add(Math.abs(d-med)); Collections.sort(dev); double mad=Math.max(1.0,dev.get(dev.size()/2));
      return 0.6745*(x-med)/mad; }
  }
  public static class Ewma { double mean=0,var=1; final double a=0.05; boolean init=false;
    public double score(double x){ if(!init){mean=x;init=true;return 0;} double d=x-mean; mean+=a*d; var=(1-a)*(var+a*d*d); return Math.abs(d)/Math.sqrt(Math.max(1,var)); }
  }
  /** Per-entity anomaly detector: EWMA+robust bytes, plus known-pattern rules. */
  public static class Detector {
    final Map<String,Ewma> ewma=new HashMap<>(), ewmaFail=new HashMap<>();
    final Map<String,Robust> robust=new HashMap<>();
    final Map<String,Deque<Event>> recent=new HashMap<>();
    final Map<String,String> lastGeo=new HashMap<>(); final Map<String,Long> lastGeoTs=new HashMap<>();
    public List<Alert> onEvent(Event e){
      List<Alert> out=new ArrayList<>(); String k=e.key();
      double zs=robust.computeIfAbsent(k,x->new Robust()).z(e.bytesOut()); robust.get(k).add((double)e.bytesOut());
      double es=ewma.computeIfAbsent(k,x->new Ewma()).score(e.bytesOut());
      if(e.bytesOut()>1_000_000||((zs>6||es>6)&&e.bytesOut()>50_000)) out.add(new Alert("data_exfiltration",k,e.user(),e.tenant(),e.ts(),Math.min(1,Math.max(zs,es)/12),"bytes_out anomaly z="+String.format("%.1f",Math.max(zs,es))));
      var dq=recent.computeIfAbsent(k,x->new ArrayDeque<>()); dq.addLast(e); while(!dq.isEmpty()&&e.ts()-dq.peekFirst().ts()>300_000)dq.pollFirst();
      long fails=dq.stream().filter(x->x.verdict().equals("block")).count();
      long dns=dq.stream().filter(x->x.source().equals("DNS")).count();
      double ent=dq.stream().filter(x->x.source().equals("DNS")).mapToDouble(Event::entropy).average().orElse(0);
      if(fails>=15) out.add(new Alert("credential_stuffing",k,e.user(),e.tenant(),e.ts(),0.95,fails+" blocked in 5m"));
      if(dns>=15&&ent>4.0) out.add(new Alert("dns_tunneling",k,e.user(),e.tenant(),e.ts(),0.93,dns+" DNS avgEntropy="+String.format("%.2f",ent)));
      String prev=lastGeo.get(k); Long pt=lastGeoTs.get(k);
      if(prev!=null&&!prev.equals(e.geo())&&pt!=null&&e.ts()-pt<3_600_000) out.add(new Alert("impossible_travel",k,e.user(),e.tenant(),e.ts(),0.9,prev+"->"+e.geo()+" in "+(e.ts()-pt)/60000+"m"));
      lastGeo.put(k,e.geo()); lastGeoTs.put(k,e.ts());
      return out;
    }
  }
  /** Cross-signal correlation: >=2 distinct sources/signals for one user in 10m -> one incident. */
  public static class Correlator {
    record Sig(String type,String source,long ts){}
    final Map<String,Deque<Sig>> buf=new HashMap<>(); final Map<String,Long> lastEmit=new HashMap<>();
    public Optional<Incident> onAlert(Alert a, String source, long ts){
      String k=a.key(); var dq=buf.computeIfAbsent(k,x->new ArrayDeque<>()); dq.addLast(new Sig(a.type(),source,ts));
      while(!dq.isEmpty()&&ts-dq.peekFirst().ts()>600_000)dq.pollFirst();
      long distinctTypes=dq.stream().map(Sig::type).distinct().count(); long distinctSrc=dq.stream().map(Sig::source).distinct().count();
      if(lastEmit.getOrDefault(k,0L)>ts-600_000) return Optional.empty();
      // Single strong rule already counts as incident; multi-signal boosts confidence.
      double conf = distinctTypes>=2||distinctSrc>=2 ? 0.97 : Math.min(0.95, 0.75+0.05*dq.size());
      lastEmit.put(k,ts);
      List<String> sigs=dq.stream().map(s->s.type()+"@"+s.source()).distinct().toList();
      return Optional.of(new Incident(a.user(),a.tenant(),ts,conf,sigs,String.join("+",sigs)));
    }
  }
}
