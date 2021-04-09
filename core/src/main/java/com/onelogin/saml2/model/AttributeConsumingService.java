package com.onelogin.saml2.model;

import java.util.ArrayList;
import java.util.List;
import com.onelogin.saml2.model.RequestedAttribute;

/**
 * AttributeConsumingService class of OneLogin's Java Toolkit.
 *
 * A class that stores AttributeConsumingService 
 */
public class AttributeConsumingService {
	/**
	 * Service Index
	 */
	private final int index;
	/**
	 * Whether this service is the default one
	 */
	private final Boolean isDefault;
	/**
     * Service Name
     */
	private final String serviceName;

	/**
     * Service Description
     */
	private final String serviceDescription;

	/**
	 * Language used for service name and description
	 */
	private final String lang;

	/**
     * Requested Attributes
     */
	private final List<RequestedAttribute> requestedAttributes;

	/**
	 * Constructor
	 * 
	 * @param index
	 *              int. Service index
	 * @param isDefault
	 *              boolean. Whether it's the default attribute consuming service
	 * @param serviceName
	 *              String. Service Name
	 * @param serviceDescription
	 *              String. Service Description
	 * @param lang
	 *              String. Language in which service name and description are
	 *              written; defaults to <code>en</code> if <code>null</code> is specified
	 */
	public AttributeConsumingService(int index, Boolean isDefault, String serviceName, String serviceDescription, String lang) {
		this.index = index;
		this.isDefault = isDefault;
		this.serviceName = serviceName != null? serviceName : "";
		this.serviceDescription = serviceDescription;
		this.lang = lang != null? lang: "en";
		this.requestedAttributes = new ArrayList<RequestedAttribute>(); 
	}

	/**
	 * Constructor. Service name and description are assumed to be in English.
	 * 
	 * @param index
	 *              int. Service index
	 * @param isDefault
	 *              boolean. Whether it's the default attribute consuming service
	 * @param serviceName
	 *              String. Service Name
	 * @param serviceDescription
	 *              String. Service Description
	 */
	public AttributeConsumingService(int index, Boolean isDefault, String serviceName, String serviceDescription) {
		this(index, isDefault, serviceName, serviceDescription, null);
	}

	/**
	 * Constructor for a non-default attribute consuming service with index
	 * <code>1</code> and service name and descriptions in English.
	 * <p>
	 * Mainly kept for backward compatibility, this constructor can be used when an
	 * only attribute consuming service is required. Please also note that, to
	 * maintain full backward compatibility, if the service description is
	 * <code>null</code> this constructor will set is as an empty string.
	 *
	 * @param serviceName
	 *              String. Service Name
	 * @param serviceDescription
	 *              String. Service Description; if <code>null</code>, an empty string will be set
	 */
	public AttributeConsumingService(String serviceName, String serviceDescription) {
		this(1, null, serviceName, serviceDescription != null? serviceDescription : "", null);
	}

	/**
	 * @param attr
	 *              RequestedAttribute. The requested attribute to be included
	 */
	public final void addRequestedAttribute(RequestedAttribute attr) {
		this.requestedAttributes.add(attr);
	}
	
	/**
	 * @return int the service index
	 */
	public final int getIndex() {
		  return index;
	}
	
	/**
	 * @return boolean whether this is the default attribute consuming service
	 */
	public final Boolean isDefault() {
		  return isDefault;
	}
	
	/**
	 * @return string the service name
	 */
	public final String getServiceName() {
		return serviceName;
	}

	/**
	 * @return string the service description
	 */
	public final String getServiceDescription() {
		return serviceDescription;
	}

	/**
	 * @return string the language in which service name and description are written
	 */
	public String getLang() {
		return lang;
	}
	
	/**
	 * @return List the requested attributes
	 */
	public final List<RequestedAttribute> getRequestedAttributes() {
		return requestedAttributes;
	}

}