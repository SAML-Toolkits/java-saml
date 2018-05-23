package com.onelogin.saml2.authn;

/**
 *	A utility class to keep a NameID sent by the IdP. 
 *	Instances of this class are used to handle the SLO request to Shibboleth IdPv3, which requires that the NameID in the SLO
 *	request carries all the four properties specified herunder - the NameIdFormat, NameQualifier, SPNameQualifier and the NameId. 
 *	Instances of NameID are immutable and thread-safe.
 * @author Rene Lauer (ray@phalanx.cz)
 */
public class NameID
{
	private final String format;
	private final String nameQualifier;
	private final String spNameQualifier;
	private final String value;

	public NameID(String format, String nameQualifier, String spNameQualifier, String value)
	{
		this.format = format;
		this.nameQualifier = nameQualifier;
		this.spNameQualifier = spNameQualifier;
		this.value = value;
	}

	public String getFormat()
	{
		return format;
	}

	public String getNameQualifier()
	{
		return nameQualifier;
	}

	public String getSpNameQualifier()
	{
		return spNameQualifier;
	}

	public String getValue()
	{
		return value;
	}
	
	public String toXML(String prefix)
	{
		String element = prefix == null ? "NameID" : prefix + ":NameID";
		return "<" + element + 
			(this.format == null ? "" : " Format=\"" + this.format + "\"") +
			(this.nameQualifier == null ? "": " NameQualifier=\"" + this.nameQualifier + "\"") +
			(this.spNameQualifier == null ? "": " SPNameQualifier=\"" + this.spNameQualifier + "\"") +
			">" +
			(this.value == null ? "" : this.value) +
			"</" + element + ">";
	}
}
