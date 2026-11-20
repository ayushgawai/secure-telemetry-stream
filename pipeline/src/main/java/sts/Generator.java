package sts;
import java.util.*;
public class Generator {
  private final Random r; private long seq=0;
  static final String[] APPS={"chat","mail","drive","code-host","video","crm","hr-portal","unknown"};
  static final String[] CATS={"business","social","streaming","file-sharing","malware","uncategorized","finance"};
  static final String[] GEOS={"US","IN","DE","BR","SG","GB"};
  static final String[] SITES={"branch-01","branch-02","branch-03","hq"};
  public Generator(long seed){r=new Random(seed);}
  private String id(){return "e-"+(++seq);}
  public Event normal(long ts){
    String tenant="tenant-"+(1+r.nextInt(3)), user="user-"+r.nextInt(200), geo=GEOS[Math.floorMod(user.hashCode(),GEOS.length)];
    String src=r.nextBoolean()?"PROXY":(r.nextBoolean()?"DNS":"FIREWALL");
    return new Event(id(),tenant,user,"dev-"+r.nextInt(300),SITES[r.nextInt(SITES.length)],ts+ r.nextInt(1000),src,
      APPS[r.nextInt(APPS.length)],CATS[r.nextInt(CATS.length)],200+r.nextInt(5000),200+r.nextInt(8000),
      r.nextInt(100)<2?"block":"allow",geo, src.equals("DNS")?"cdn.example.com":"",1.5+r.nextDouble()*2,null,null,"10.0."+r.nextInt(20)+"."+r.nextInt(250));
  }
  public List<Event> generate(int n){List<Event> out=new ArrayList<>(n); long base=1_700_000_000_000L; for(int i=0;i<n;i++) out.add(normal(base+i*100L)); return out;}
  String randStr(int n){String c="abcdefghijklmnopqrstuvwxyz0123456789"; StringBuilder b=new StringBuilder(); for(int i=0;i<n;i++)b.append(c.charAt(r.nextInt(c.length()))); return b.toString();}
  public List<Event> credentialStuffing(long ts,String user){
    List<Event> out=new ArrayList<>(); String aid="atk-"+(++seq);
    for(int i=0;i<40;i++) out.add(new Event(id(),"tenant-1",user,"dev-x","branch-01",ts+i*500,"PROXY","mail","business",300,300,"block","US","",0,aid,"credential_stuffing","185.0.0."+i));
    return out;
  }
  public List<Event> dnsTunneling(long ts,String user){
    List<Event> out=new ArrayList<>(); String aid="atk-"+(++seq);
    for(int i=0;i<40;i++){String q=randStr(48)+".tunnel.example.com"; out.add(new Event(id(),"tenant-1",user,"dev-x","branch-01",ts+i*500,"DNS","unknown","uncategorized",600,600,"allow","US",q,4.6,aid,"dns_tunneling","10.0.0.9"));}
    return out;
  }
  public List<Event> exfiltration(long ts,String user){
    List<Event> out=new ArrayList<>(); String aid="atk-"+(++seq);
    for(int i=0;i<25;i++) out.add(new Event(id(),"tenant-1",user,"dev-x","branch-02",ts+i*500,"PROXY","unknown","file-sharing",100,8_000_000+r.nextInt(2_000_000),"allow","DE","",0,aid,"data_exfiltration","10.0.0.8"));
    return out;
  }
  public List<Event> impossibleTravel(long ts,String user){
    String aid="atk-"+(++seq);
    return List.of(
      new Event(id(),"tenant-1",user,"dev-x","hq",ts,"PROXY","mail","business",500,500,"allow","US","",0,aid,"impossible_travel","10.0.0.1"),
      new Event(id(),"tenant-1",user,"dev-x","hq",ts+600_000,"PROXY","mail","business",500,500,"allow","BR","",0,aid,"impossible_travel","187.0.0.1"));
  }
  /** Mixed stream with labeled attacks; each attack burst repeated for detector warm-up realism. */
  public List<Event> mixed(int n){
    List<Event> out=generate(n); long ts=1_700_000_000_000L+n*100L+10_000;
    for(int k=0;k<4;k++){ out.addAll(credentialStuffing(ts+k*100_000,"victim-cred-"+k)); out.addAll(dnsTunneling(ts+50_000+k*100_000,"victim-dns-"+k)); out.addAll(exfiltration(ts+25_000+k*100_000,"victim-exfil-"+k)); out.addAll(impossibleTravel(ts+75_000+k*100_000,"victim-travel-"+k)); }
    out.sort(Comparator.comparingLong(Event::ts)); return out;
  }
}
