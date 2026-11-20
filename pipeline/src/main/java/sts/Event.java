package sts;
import java.util.*;
public record Event(String eventId,String tenant,String user,String device,String site,long ts,String source,
  String app,String category,long bytesIn,long bytesOut,String verdict,String geo,String query,double entropy,
  String attackId,String attackType,String srcIp){
  public String key(){return tenant+"|"+user;}
  public String toJson(){
    return String.format(Locale.ROOT,"{\"event_id\":\"%s\",\"tenant\":\"%s\",\"user\":\"%s\",\"device\":\"%s\",\"site\":\"%s\",\"ts\":%d,\"source\":\"%s\",\"app\":\"%s\",\"category\":\"%s\",\"bytes_in\":%d,\"bytes_out\":%d,\"verdict\":\"%s\",\"geo\":\"%s\",\"query\":\"%s\",\"entropy\":%.2f,\"attack_type\":\"%s\"}",
      esc(eventId),esc(tenant),esc(user),esc(device),esc(site),ts,source,esc(app),esc(category),bytesIn,bytesOut,verdict,esc(geo),esc(query),entropy,attackType==null?"":attackType);
  }
  static String esc(String s){return s==null?"":s.replace("\\","\\\\").replace("\"","\\\"");}
  public static Event parseJson(String j){ // ponytail: tiny extractor for our own JSONL, use Jackson in prod if schema grows
    return new Event(s(j,"event_id"),s(j,"tenant"),s(j,"user"),s(j,"device"),s(j,"site"),l(j,"ts"),s(j,"source"),s(j,"app"),s(j,"category"),l(j,"bytes_in"),l(j,"bytes_out"),s(j,"verdict"),s(j,"geo"),s(j,"query"),d(j,"entropy"),null,s(j,"attack_type").isEmpty()?null:s(j,"attack_type"),"");
  }
  static String s(String j,String k){int i=j.indexOf("\""+k+"\":\""); if(i<0)return ""; int a=j.indexOf('"',i+k.length()+3); int b=j.indexOf('"',a+1); return j.substring(a+1,b);}
  static long l(String j,String k){int i=j.indexOf("\""+k+"\":"); int a=j.indexOf(':',i)+1; int b=a; while(b<j.length()&&(Character.isDigit(j.charAt(b))||j.charAt(b)=='-'))b++; return Long.parseLong(j.substring(a,b));}
  static double d(String j,String k){try{int i=j.indexOf("\""+k+"\":"); int a=j.indexOf(':',i)+1; int b=a; while(b<j.length()&&"0123456789.-".indexOf(j.charAt(b))>=0)b++; return Double.parseDouble(j.substring(a,b));}catch(Exception e){return 0;}}
}
