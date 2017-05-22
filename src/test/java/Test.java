import com.threatconnect.sdk.client.reader.AbstractGroupReaderAdapter;
import com.threatconnect.sdk.client.reader.ReaderAdapterFactory;
import com.threatconnect.sdk.config.Configuration;
import com.threatconnect.sdk.conn.Connection;
import com.threatconnect.sdk.server.entity.Adversary;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by gerry on 4/23/2017.
 */
public class Test {
    public static void main(String[] args) {

       // StixProducer.produceForThrear("DDos.5.6");
        //Calendar cal = HelperMethods.getDateFromString("06 Mar 2017");
        //System.out.println(cal.getTime());

     //   ParsersFromRssClass.getFromMalshare();
        Map<String,String> testMap = new HashMap<String, String>();
        testMap.put("HASHTYPE","MD5");
        testMap.put("MD5HASH","123cbr23423fnn23rn");
        testMap.put("HOST","testhost.com");
        testMap.put("IP","192.168.1.8");

        StixProducer.produceForBadHost(testMap);
        //Testiong ThreatCOnnect SDK
        Connection conn = null;

        try {
                        Configuration configuration = new Configuration("ttps://api.threatconnect.com/v2/","","","gerrybezhani");
                         conn = new Connection();

                        AbstractGroupReaderAdapter<Adversary> reader = ReaderAdapterFactory.createAdversaryGroupReader(conn);
                         List<Adversary> data = (List<Adversary>) reader.getAll("System");
                         for (Adversary g : data ) {
                             System.out.println( "Adversary: " + g.toString() );
                        }

                     } catch (IOException ex ) {
                         System.err.println("Error: " + ex);
                     } finally {
                         if ( conn != null )     conn.disconnect();
                     }

    }
}
