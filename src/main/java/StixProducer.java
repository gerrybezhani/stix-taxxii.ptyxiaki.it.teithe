import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import org.apache.commons.lang.StringUtils;
import org.mitre.cybox.common_2.ObjectFactory;
import org.mitre.cybox.common_2.StringObjectPropertyType;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.stix.common_1.*;
import org.mitre.stix.courseofaction_1.CourseOfAction;
import org.mitre.stix.exploittarget_1.CVSSVectorType;
import org.mitre.stix.exploittarget_1.ExploitTarget;
import org.mitre.stix.exploittarget_1.PotentialCOAsType;
import org.mitre.stix.exploittarget_1.VulnerabilityType;
import org.mitre.stix.indicator_2.Indicator;
import org.mitre.stix.stix_1.*;
import org.mitre.stix.ttp_1.*;
import org.mitre.stix.ttp_1.ExploitTargetsType;

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
                .withDescriptions(new StructuredTextType().withValue(content.get("Description")))
                .withShortDescriptions(new StructuredTextType().withValue(content.get("Overview")))
                .withCVEID(content.get("Other Information"))
                .withReferences(new ReferencesType().withReferences(content.get("References")))
                .withCVEID(null)
                .withPublishedDateTime(null)
                .withPublishedDateTime(null);

        VictimTargetingType victimTargetingType = new VictimTargetingType().
                withIdentity(new IdentityType().withName(content.get("Vendor Information")));

        CVSSVectorType cvssVectorType = new CVSSVectorType();
        vulnerabilityType.withCVSSScore(cvssVectorType);

        InformationSourceType informationSourceType = new InformationSourceType()
                .withDescriptions(new StructuredTextType().withValue(content.get("Credit")));
        ExploitTargetBaseType exploitTargetBaseType = new ExploitTarget()
                .withInformationSource(informationSourceType );

        exploitTarget.withVulnerabilities(vulnerabilityType);

        CourseOfActionBaseType courseOfActionBaseType = new CourseOfAction()
                .withDescriptions(new StructuredTextType().withValue(content.get("Solution")));

        RelatedCourseOfActionType relatedCourseOfActionType = new RelatedCourseOfActionType()
                .withCourseOfAction(courseOfActionBaseType);

        exploitTarget.withPotentialCOAs(
                new PotentialCOAsType().withPotentialCOAs(relatedCourseOfActionType)
        );






        RelatedExploitTargetType exploitTargetType = new RelatedExploitTargetType()
                .withExploitTarget(exploitTarget);



        AttackPatternType attackPatternType = new AttackPatternType().withDescriptions(new StructuredTextType().withValue(content.get("Impact")));

        TTP ttp = new TTP()
                .withBehavior(new BehaviorType()
                        .withAttackPatterns(new AttackPatternsType().withAttackPatterns(attackPatternType)))
                .withExploitTargets(new ExploitTargetsType().withExploitTargets(exploitTargetType))
                .withVictimTargeting(victimTargetingType);


        XMLGregorianCalendar now = null;
        try {
            now = DatatypeFactory.newInstance()
                    .newXMLGregorianCalendar(
                            new GregorianCalendar(TimeZone.getTimeZone("UTC")));
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }

        STIXHeaderType stixHeader = new STIXHeaderType()
                .withDescriptions(new StructuredTextType()
                        .withValue("CVE exploit"));

        STIXPackage stixPackage = new STIXPackage()
                .withSTIXHeader(stixHeader)
                .withTTPs(new TTPsType().withTTPS(ttp))
                .withVersion("1.2")
                .withTimestamp(now)
                .withId(new QName("gerry.ptyxiaki.it.teithe", "package-"
                        + UUID.randomUUID().toString(), "gerry"));

        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());
    }

}
