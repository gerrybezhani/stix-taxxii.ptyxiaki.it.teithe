import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import org.apache.commons.lang.StringUtils;
import org.mitre.cybox.common_2.ObjectFactory;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.IndicatorBaseType;
import org.mitre.stix.common_1.StructuredTextType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;

import javax.xml.bind.JAXBContext;
import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

/**
 * Created by gerry on 4/14/2017.
 */
public class StixProducer {

    public static void produce(String IP)
    {

        StringObjectPropertyType stringObjectPropertyType = (new ObjectFactory()).createStringObjectPropertyType().withValue(IP);
        Address addr = new Address()
                .withAddressValue(stringObjectPropertyType)
                .withCategory(CategoryTypeEnum.IPV_4_ADDR)
                .withIsSource(true);


        ObjectType objt = new ObjectType().withProperties(addr).withId(new QName(UUID.randomUUID().toString()));
        Observable obs = new Observable();

        obs.setObject(objt);
        final Indicator indicator = new Indicator()
                .withId(new QName(UUID.randomUUID().toString()))
                .withTimestamp(null)
                .withTitle("R")
                .withDescriptions(
                        new StructuredTextType()
                        .withValue("Ip containign malware")
                ).withObservable(obs);

        IndicatorsType indicators = new IndicatorsType(
                new ArrayList<IndicatorBaseType>() {
                    {
                        add(indicator);
                    }
                });

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("Example"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withIndicators(indicators)
                .withVersion("1.2")
                .withTimestamp(null)
                .withId(new QName("http://example.com/", "package-"
                        + UUID.randomUUID().toString(), "example"));

        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());
    }

    public static void cveGen(Map<String,String> content)
    {

        DateTimeWithPrecisionType dt = new DateTimeWithPrecisionType();

        ExploitTarget exploitTarget = new ExploitTarget();
        VulnerabilityType vulnerabilityType = new VulnerabilityType().
                withTitle(content.get("Title"))
                .withDescriptions(StructuredTextType.fromXMLString(content.get("Description")))
                .withShortDescriptions(StructuredTextType.fromXMLString(content.get("Overview")))
                .withCVEID(content.get("Other Information"))
                .withPublishedDateTime(null);


    }
}
