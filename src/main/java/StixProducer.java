import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import org.apache.commons.lang.StringUtils;
import org.mitre.cybox.common_2.ObjectFactory;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.stix.common_1.*;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.CoursesOfActionType;
import org.mitre.stix.stix_1.IndicatorsType;
import org.mitre.stix.stix_1.STIXHeaderType;
import org.mitre.stix.stix_1.STIXPackage;
import org.mitre.stix.ttp_1.AttackPatternsType;
import org.mitre.stix.ttp_1.BehaviorType;
import org.mitre.stix.ttp_1.TTP;
import org.mitre.stix.ttp_1.VictimTargetingType;

import javax.xml.bind.JAXBContext;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.util.*;

/**
 * Created by gerry on 4/14/2017.
 */
public class StixProducer {

    public static void produce(String IP,String type) {
        XMLGregorianCalendar now = null;
        try {
            now = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(
                            new GregorianCalendar(TimeZone.getTimeZone("UTC")));
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }


        StringObjectPropertyType stringObjectPropertyType = (new ObjectFactory()).createStringObjectPropertyType().withValue(IP);
        Address addr = new Address()
                .withAddressValue(stringObjectPropertyType)
                .withCategory(CategoryTypeEnum.IPV_4_ADDR)
                .withIsSource(true);


        ObjectType objt = new ObjectType().withProperties(addr).withId(new QName("gerry.ptyxiaki.it.teithe", "observable-"
                + UUID.randomUUID().toString(), "gerry"));
        Observable obs = new Observable();

        obs.setObject(objt);
        final Indicator indicator = new Indicator()
                .withId(new QName(UUID.randomUUID().toString()))
                .withTimestamp(now)
                .withTitle(type)
                .withDescriptions(
                        new StructuredTextType()
                                .withValue("Ip Watchlist")
                ).withObservable(obs);

        IndicatorsType indicators = new IndicatorsType(
                new ArrayList<IndicatorBaseType>() {
                    {
                        add(indicator);
                    }
                });

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("IP WATCHLIST"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withIndicators(indicators)
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"));

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
                .withReferences(ReferencesType.fromXMLString(content.get("References")))
                .withCVEID(null)
                .withPublishedDateTime(null)
                .withPublishedDateTime(null);

        VictimTargetingType victimTargetingType = new VictimTargetingType().
                withIdentity(IdentityType.fromXMLString(content.get("Vendor Information")));

        CVSSVectorType cvssVectorType = new CVSSVectorType();

        ExploitTargetBaseType exploitTargetBaseType = new ExploitTarget()
                .withInformationSource(InformationSourceType.fromXMLString(content.get("Credit")));

        TTP ttp = new TTP()
                .withBehavior(new BehaviorType()
                        .withAttackPatterns(AttackPatternsType.fromXMLString(content.get("Impact"))))
                ;

        CoursesOfActionType coursesOfActionType = new CoursesOfActionType()
                .withCourseOfActions(CourseOfActionBaseType.fromXMLString(content.get("Solution")));

        PotentialCOAsType potentialCOAsType = new PotentialCOAsType();
        exploitTarget.withVulnerabilities(vulnerabilityType);
        //exploitTarget.withPotentialCOAs(coursesOfActionType)

    }
}
