import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * Created by gerry on 4/23/2017.
 */
public class HelperMethods {

    public static Calendar getDateFromString(String dateStr)
    {
        DateFormat df = new SimpleDateFormat("dd MMM yyyy");
        Date date = null;
        try {
            date = df.parse(dateStr);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        Calendar cal = new GregorianCalendar();

        cal.setTime(date);

        return cal;
    }
}
