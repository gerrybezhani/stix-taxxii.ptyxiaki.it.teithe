import com.sun.org.apache.xerces.internal.jaxp.datatype.XMLGregorianCalendarImpl;
import org.apache.commons.lang.StringUtils;
import org.mitre.cybox.common_2.*;
import org.mitre.cybox.common_2.ObjectFactory;
import org.mitre.cybox.cybox_2.ObjectType;
import org.mitre.cybox.cybox_2.Observable;
import org.mitre.cybox.default_vocabularies_2.HashNameVocab10;
import org.mitre.cybox.objects.Address;
import org.mitre.cybox.objects.CategoryTypeEnum;
import org.mitre.cybox.objects.FileObjectType;
import org.mitre.stix.common_1.*;
import org.mitre.stix.common_1.DateTimeWithPrecisionType;
import org.mitre.stix.common_1.StructuredTextType;
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

    //method that produces stix content for hashes of files

    public static void produceForFileHash()
    {
        XMLGregorianCalendar now = HelperMethods.getTime();
        FileObjectType fileObject = new FileObjectType()
                .withHashes(new HashListType(new ArrayList<HashType>() {
                    {
                        add(new HashType()
                                .withType(
                                        new HashNameVocab10()
                                                .withValue("MD5"))
                                .withSimpleHashValue(
                                        new SimpleHashValueType()
                                                .withValue("4EC0027BEF4D7E1786A04D021FA8A67F")));
                    }
                }));

        ObjectType obj = new ObjectType().withProperties(fileObject)
                .withId(new QName("http://example.com/", "file-"
                        + UUID.randomUUID().toString(), "example"));

        Observable observable = new Observable().withId(new QName(
                "http://example.com/", "observable-"
                + UUID.randomUUID().toString(), "example"));

        observable.setObject(obj);

        IdentityType identity = new IdentityType()
                .withName("The MITRE Corporation");

        InformationSourceType producer = new InformationSourceType()
                .withIdentity(identity)
                .withTime(
                        new TimeType()
                                .withProducedTime(new org.mitre.cybox.common_2.DateTimeWithPrecisionType(now,null)));

        final Indicator indicator = new Indicator()
                .withId(new QName("http://example.com/", "indicator-"
                        + UUID.randomUUID().toString(), "example"))
                .withTimestamp(now)
                .withTitle("File Hash Example")
                .withDescriptions(
                        new StructuredTextType()
                                .withValue("An indicator containing a File observable with an associated hash"))
                .withObservable(observable).withProducer(producer);

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
                .withTimestamp(now)
                .withId(new QName("http://example.com/", "package-"
                        + UUID.randomUUID().toString(), "example"));

        System.out.println(stixPackage.toXMLString(true));

        System.out.println(StringUtils.repeat("-", 120));

        System.out.println("Validates: " + stixPackage.validate());


    }

    public static void produce(String IP,String type) {

        XMLGregorianCalendar now = HelperMethods.getTime();

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


        XMLGregorianCalendar now = HelperMethods.getTime();

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
