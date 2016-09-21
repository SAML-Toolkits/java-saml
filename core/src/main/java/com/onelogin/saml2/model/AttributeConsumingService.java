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
     * Service Name
     */
	private final String serviceName;

	/**
     * Service Description
     */
	private final String serviceDescription;

	/**
     * Requested Attributes
     */
	private final List<RequestedAttribute> requestedAttributes;

	/**
	 * Constructor
	 *
	 * @param serviceName
	 *              String. Service Name
	 * @param serviceDescription
	 *              String. Service Description
	 */
	public AttributeConsumingService(String serviceName, String serviceDescription) {
		this.serviceName = serviceName != null? serviceName : "";
		this.serviceDescription = serviceDescription != null? serviceDescription : "";
		this.requestedAttributes = new ArrayList<RequestedAttribute>(); 
	}

	/**
	 * @param attr
	 *              RequestedAttribute. The requested attribute to be included
	 */
	public final void addRequestedAttribute(RequestedAttribute attr) {
		this.requestedAttributes.add(attr);
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
	 * @return List<RequestedAttribute> the requested attributes
	 */
	public final List<RequestedAttribute> getRequestedAttributes() {
		return requestedAttributes;
	}

}