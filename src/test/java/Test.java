import java.util.Calendar;

/**
 * Created by gerry on 4/23/2017.
 */
public class Test {
    public static void main(String[] args) {

        Calendar cal = HelperMethods.getDateFromString("06 Mar 2017");
        System.out.println(cal.getTime());
    }
}
