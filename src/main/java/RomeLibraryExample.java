import Exceptions.UriNotFoundException;

import java.util.ArrayList;
import java.util.Map;


public class RomeLibraryExample {




    public static void main(String[] args){

        ArrayList<String> urls = AdressesClass.getUrls();


        ArrayList<Map<String,String>> parsedCont = ParsersFromRssClass.parseRssFeeds("http://www.kb.cert.org/vulfeed");
        try {
            ArrayList<Map<String,String>> cleanedCont = CleanUpClass.cleanUp(parsedCont);
        } catch (UriNotFoundException e) {
            e.printStackTrace();
        }

        System.out.println(parsedCont);
        System.out.println("-----------------------------------");
            System.out.println();




    }
}