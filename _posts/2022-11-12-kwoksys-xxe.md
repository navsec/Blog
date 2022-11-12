---
title: "Kwoksys 2.9.5 XXE"
date: 2022-11-12
---


*This was disclosed with permission from the Kwoksys development team*


In preparation to take my OSWE (Offensive Security Web Expert) exam, I've been auditing open source projects for security vulnerabilities to augment my study material. One of these projects that I stumbled upon was Kwoksys.

Kwoksys is an open source IT management system that provides a centralized system for manging/tracking inventory, software licenses, issues, service contracts, and vendor contacts. Additionally, Kwoksys provides modules for building internal knowledge bases, portals, RSS feeds, and blogs. The project has been actively maintained since 2007 and has been downloaded 86,000+ times at the time of writing this blog post.

The project is built on a Tomcat stack and uses a postgresql database for its backend.




I spent a significant amount of time probing the application as an unauthenticated user with little success. The application has a very light unauthenticated presence with very few routes accessible without authentication.

The login process was also solid and . The application offers no password reset option without authentication - further limiting our options.

As a last resort - I searched for XSS vulnerabilities within files accessible without authentication but was unsuccessful.

Satisfied with my review of the unauthenticated scope, I decided to switch to probing the application as an authenticated user.

After authenticating to the application we have access to a lot more modules to review. We'll focus on the RSS module.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112110829.png)

Kwoksys allows an authenticated and sufficiently privileged user to be able to add a custom RSS feed.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112113053.png)

RSS feeds traditionally use XML as the underlying data-interchange format. 

Wikipedia:
*An RSS document (called "feed", "web feed",[4] or "channel") includes full or summarized text, and metadata, like publishing date and author's name. RSS formats are specified using a generic XML file.*

Here's an example of a basic RSS feed in XML format:
```XML
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
	<title>An Awesome Blog</title>
	<link>http://example.com/</link>
	<description>A blog about things</description>
	<lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
	<item>
		<title>An Awesome Blog</title>
		<link>http://example.com</link>
		<description>a post</description>
		<author>author@example.com</author>
		<pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
	</item>
</channel>
</rss>
```

As a security researcher this is definitely a component we need to review. Since the RSS feed has to support XML data, we can infer that some form of XML parsing is being done server-side. If the XML parser is weakly configured - we might be able to achieve XXE (XML External Entity) injection. For more information on XXE vulnerabilities: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing


Decompiling the kwok-2.9.5.jar in JD-GUI, we see that logic for the RSS parser is contained under com.kwoksys.framework.parsers.rss.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112113341.png)

The developers are using standard libraries to perform XML parsing and are using apache axiom libraries for XML modeling. However, they also appear to have some custom logic for RSS parsing in the form of com.kwoksys.framework.util.XmlUtils. When conducting code reviews for vulnerabilities, custom code deserves serious scrutiny.

Standard libraries and popular 3rd party dependencies are less likely to contain vulnerabilities than custom code specific to the application being tested. Those libraries have had more eyes on them and have been battle-tested while the application-specific code may have had a lot less attention and review.

Reviewing the custom code for XmlUtils, we see a single method that appears to append an XML version tag to an XML object that is passed to it.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112115833.png)

Let's search for calls to the XmlUtils class within our RSS parsing classes to see where this is being done. Our search reveals that XmlUtils is only called one time and it's within the modelToXml class. We can infer that this class is called when converting a model to XML.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112115547.png)

Since this is converting from a model to XML - this custom code is being called after the incoming XML has already been parsed and converted into a model. This isn't helpful for us - we need to review the code that converts XML to a model as that is where an XXE vulnerability would be present.

Let's more closely review the xmlToModel class which sounds like the process we are looking for.

```java
public void xmlToModel(String xmlString) throws Exception {
    this.xmlString = xmlString;
    this.rssModel = new RssModel();
    StringReader reader = new StringReader(xmlString);
    XMLStreamReader parser = XMLInputFactory.newInstance().createXMLStreamReader(reader);
    StAXOMBuilder stAXOMBuilder = OMXMLBuilderFactory.createStAXOMBuilder(OMAbstractFactory.getOMFactory(), parser);
    OMElement rss = stAXOMBuilder.getDocumentElement();
    OMElement channel = rss.getFirstElement();
    buildChannel(channel);
  }
```

The class takes an XML string as input and sets it as a variable. It instantiates several new objects in the form of **rssModel**, **reader**, and **parser**. 

The reader object is an instance of StringReader with the original XML input passed in.

The parser object is instantiated as an instance of XMLInputFactory and the reader object is passed in.

As we read further in the class - we notice that the rest of the logic relates to the data modeling process - which occurs after our XML input is processed.

We need to zero-in on the XMLInputFactory class as that contains the parser logic we are looking for. As we identified earlier, XMLInputFactory is sourced from javax.xml.stream. We need to figure out if XMLInputFactory supports external entities by default. We can review Oracle documentation for more information on the XMLInputFactory class. Since we know the newInstance() method is called, let's search for that.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112123106.png)

It looks like the newInstance() method performs the same function as the newFactory() method. This is likely a legacy method and is still in-use to maintain backwards-compatability. Let's review the newFactory() method.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112123237.png)
Reviewing the constants for XMLInputFactory we find:
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112124013.png)
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112124034.png)

Now that we have found the property that configures external entity support - we can review the Oracle documentation to see what the default value is.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112124115.png)


According to the documentation, the default value of the isSupportingExternalEntities is "Unspecified". It is unclear what that means or how the application will interpret this. We need to dig deeper into the standard library to understand how this is being implemented.

The openjdk repository on github provides us with the source code for the **XMLInputFactory** class.
https://github.com/openjdk/jdk/blob/master/src/java.xml/share/classes/javax/xml/stream/XMLInputFactory.java

You can review the source code in-depth at the link provided above. But for the purposes of this blog we will condense the relevant sections:

/src/java.xml/share/classes/javax/xml/stream/XMLInputFactory.java
```java
//CONDENSED

// The XMLInputFactoryImpl is imported
import com.sun.xml.internal.stream.XMLInputFactoryImpl;


// The property of IS_SUPPORTING_EXTERNAL_ENTITIES is set to the value of javax.xml.stream.isSupportingExternalEntities
public static final String IS_SUPPORTING_EXTERNAL_ENTITIES=
"javax.xml.stream.isSupportingExternalEntities";


// A default implementor is set.
static final String DEFAULIMPL = "com.sun.xml.internal.stream.XMLInputFactoryImpl";

// A call to newDefaultFactory() calls XMLInputFactoryImpl() from com.sun.xml.internal.stream.XMLInputFactoryImpl
public static XMLInputFactory newDefaultFactory() {
	return new XMLInputFactoryImpl();
}

// The method to create a new factory using the Default Implementation set earlier.
public static XMLInputFactory newFactory()
	throws FactoryConfigurationError
{
return FactoryFinder.find(XMLInputFactory.class, DEFAULIMPL);
}
```

So now we know that our factory instance is being created based on the implementation of XMLInputFactoryImpl. We now need to review the source code for **com.sun.xml.internal.stream.XMLInputFactoryImpl**
https://github.com/openjdk/jdk/blob/master/src/java.xml/share/classes/com/sun/xml/internal/stream/XMLInputFactoryImpl.java

``` Java
// CONDENSED

// An import for PropertyManager
import com.sun.org.apache.xerces.internal.impl.PropertyManager;

// Factory Implementation for XMLInputFactory.
public class XMLInputFactoryImpl extends javax.xml.stream.XMLInputFactory {

//List of supported properties and default values.
private PropertyManager fPropertyManager = new PropertyManager(PropertyManager.CONTEXT_READER) ;
```

Based on the code within XMLInputFactoryImpl - we see that an instance of PropertyManager is created with the argument of PropertyManager.CONTEXT_READER. Once again, we need to review another file to see if the external entity settings are configured.

We will review **com.sun.org.apache.xerces.internal.impl.PropertyManager**
https://github.com/openjdk/jdk/blob/master/src/java.xml/share/classes/com/sun/org/apache/xerces/internal/impl/PropertyManager.java

```Java
private void initConfigurableReaderProperties() {

//Setting Default Property Values
supportedProps.put(XMLInputFactory.IS_NAMESPACE_AWARE, Boolean.TRUE);
supportedProps.put(XMLInputFactory.IS_VALIDATING, Boolean.FALSE);
supportedProps.put(XMLInputFactory.IS_REPLACING_ENTITY_REFERENCES, Boolean.TRUE);
supportedProps.put(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.TRUE);
supportedProps.put(XMLInputFactory.IS_COALESCING, Boolean.FALSE);
supportedProps.put(XMLInputFactory.SUPPORT_DTD, Boolean.TRUE);
supportedProps.put(XMLInputFactory.REPORTER, null);
supportedProps.put(XMLInputFactory.RESOLVER, null);
supportedProps.put(XMLInputFactory.ALLOCATOR, null);
supportedProps.put(STAX_NOTATIONS, null);
```

We can now confirm that the **IS_SUPPORTING_EXTERNAL_ENTITIES** is by default enabled! 

Now that we know that the default implementation for new instances of XMLInputFactory allows for external entities. Let's review the Kwoksys source once again.

```Java
public void xmlToModel(String xmlString) throws Exception {
    this.xmlString = xmlString;
    this.rssModel = new RssModel();
    StringReader reader = new StringReader(xmlString);
    XMLStreamReader parser = XMLInputFactory.newInstance().createXMLStreamReader(reader);
    StAXOMBuilder stAXOMBuilder = OMXMLBuilderFactory.createStAXOMBuilder(OMAbstractFactory.getOMFactory(), parser);
    OMElement rss = stAXOMBuilder.getDocumentElement();
    OMElement channel = rss.getFirstElement();
    buildChannel(channel);
  }
```

After reviewing the code - there is no manual configuration of the **IS_SUPPORTING_EXTERNAL_ENTITIES** property. This parser should be vulnerable to XXE.


## **Exploitation**

The following XXE payload can be used to confirm our theory
```XML
<!DOCTYPE title [ <!ELEMENT title ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
        <channel>
            <title>Evil Blog</title>
            <link>http://example.com/</link>
            <description>A blog about things</description>
            <lastBuildDate>Mon, 03 Feb 2014 00:00:00 -0000</lastBuildDate>
            <item>
                <title>&xxe;</title>
                <link>http://example.com</link>
                <description>a post</description>
                <author>author@example.com</author>
                <pubDate>Mon, 03 Feb 2014 00:00:00 -0000</pubDate>
            </item>
        </channel>
        </rss>
```

If the parser is vulnerable, it will attempt to resolve the external entity "xxe" declared above. Since the external entity points to "file:///etc/passwd", the parser should include the content of the system's /etc/passwd file within the &xxe reference contained in the title tag.

First, we host our malicious xml file on another server:
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112135504.png)

From within Kwoksys, we add a new RSS feed pointing to our web server
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112135615.png)

After clicking 'Add', we notice that Kwoksys has reached out to our web server for the XML file.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112135946.png))

Back on Kwoksys we see that there is a new blog entry:
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112140030.png)
We have successfully exploited an external entity injection vulnerability. By changing the external entity value in the XML payload - we can now arbitrarily read any file on the server's filesystem.

To speed up exploitation, we can build a script to change the XML payload based on whatever file we specify and to trigger a refresh of the RSS feed. Giving us a read-only psuedo shell to the system! Much faster!
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112141409.png)
The exploit PoC script has been published to exploitDB here: 

#### Impact

XXE vulnerabilities are included in the OWASP Top 10 and are usually classified as high severity. As we've covered, XXE can be used to obtain access to sensitive configuration files on the local host, potentially leading to RCE.

External entities can also point to remote locations, such as a web service running on another system. As an example, let's say that the Kwoksys system can reach other systems within its internal network that are inaccessible to an attacker. An attacker could leverage XXE to make requests from the Kwoksys server (SSRF (Server-Side Request Forgery)). Alternatively, using a time-based approach, an attacker could use XXE to map out an internal network to see what hosts are alive based on how quickly the server can process an external entity to a remote server.


#### Patch Review

After reporting this to the Kwoksys team - they quickly deployed a patch [2.9.5.SP31] which addresses this.
![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112104410.png)

As this is an open source project, let's review the mitigations implemented by the developers.

![Image](/images/2022-11-12-kwoksys-xxe/Pasted image 20221112142936.png)

The developers manually overrided 'IS_SUPPORTING_EXTERNAL_ENTITIES' to false to disable all support for external entities effectively eliminating the XXE vulnerability.


### Key Takeaways

While much less common nowadays, some XML parsing libraries still have external entity support enabled by default instead of disabled by default. In this case, the default implementation of the XMLInputFactory provided support for external entities and the implementation was far abstracted from where the class was instantiated making the value of this property less visible to the developers.

When hunting for vulnerabilities, your eyes should be drawn to custom code. However, don't neglect standard libraries or popular 3rd party libraries. Ultimately, some libraries can be insecure depending on how they are brought into an application to be used.

Thank you for reading!


