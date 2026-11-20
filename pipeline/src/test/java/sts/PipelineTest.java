package sts;
import org.junit.jupiter.api.Test; import static org.junit.jupiter.api.Assertions.*; import java.util.*;
class PipelineTest {
  @Test void dedupAndWindows(){ var g=new Generator(1); var ev=g.generate(1000); ev.add(ev.get(0));
    var r=new Pipeline().run(ev,new Pipeline.MemorySink()); assertEquals(1000,r.processed()); assertEquals(1,r.deduped()); assertFalse(r.aggregates().isEmpty()); }
  @Test void detectorsFirePerAttack(){ var g=new Generator(2);
    assertDetected(g.credentialStuffing(1_700_000_000_000L,"victim-cred-0"),"credential_stuffing");
    assertDetected(g.dnsTunneling(1_700_000_000_000L,"victim-dns-0"),"dns_tunneling");
    assertDetected(g.exfiltration(1_700_000_000_000L,"victim-exfil-0"),"data_exfiltration");
    assertDetected(g.impossibleTravel(1_700_000_000_000L,"victim-travel-0"),"impossible_travel"); }
  void assertDetected(List<Event> ev,String type){ var r=new Pipeline().run(ev,new Pipeline.MemorySink());
    assertTrue(r.incidents().stream().anyMatch(i->i.summary().contains(type)), type+" not in "+r.incidents()); }
  @Test void normalTrafficFewIncidents(){ var r=new Pipeline().run(new Generator(3).generate(5000),new Pipeline.MemorySink());
    assertTrue(r.incidents().size()<50,"too many false incidents: "+r.incidents().size()); }
  @Test void robustAndEwma(){ var rz=new Detectors.Robust(); for(int i=0;i<50;i++)rz.add(100); assertTrue(rz.z(100000)>6);
    var ew=new Detectors.Ewma(); for(int i=0;i<50;i++)ew.score(100); assertTrue(ew.score(100000)>3); }
  @Test void partitionStable(){ assertEquals(Pipeline.partitionFor("tenant-1",12),Pipeline.partitionFor("tenant-1",12)); }
  @Test void jsonRoundTrip(){ var e=new Generator(4).normal(123); var p=Event.parseJson(e.toJson()); assertEquals(e.eventId(),p.eventId()); assertEquals(e.bytesOut(),p.bytesOut()); }
}
