package com.onelogin.saml2.authn;

import java.util.List;

import com.onelogin.saml2.model.AttributeConsumingService;
import com.onelogin.saml2.settings.Saml2Settings;

/**
 * Interfaced used to select the Attribute Consuming Service to be specified in
 * an authentication request. An instance of this interface can be passed as an
 * input parameter in a {@link AuthnRequestParams} to be used when initiating a
 * login operation.
 * <p>
 * A set of predefined implementations are provided: they should cover the most
 * common cases.
 */
@FunctionalInterface
public interface AttributeConsumingServiceSelector {

	/**
	 * @return a selector of the default Attribute Consuming Service
	 */
	static AttributeConsumingServiceSelector useDefault() {
		return () -> null;
	}

	/**
	 * @param attributeConsumingService
	 *              the Attribute Consuming Service to select
	 * @return a selector the chooses the specified Attribute Consuming Service;
	 *         indeed, its index is used
	 */
	static AttributeConsumingServiceSelector use(final AttributeConsumingService attributeConsumingService) {
		return byIndex(attributeConsumingService.getIndex());
	}

	/**
	 * @param index
	 *              the index of the Attribute Consuming Service to select
	 * @return a selector that chooses the Attribute Consuming Service with the
	 *         given index
	 */
	static AttributeConsumingServiceSelector byIndex(final int index) {
		return () -> index;
	}

	/**
	 * @param settings
	 *              the SAML settings, containing the list of the available
	 *              Attribute Consuming Services (see
	 *              {@link Saml2Settings#getSpAttributeConsumingServices()})
	 * @param serviceName
	 *              the name of the Attribute Consuming Service to select
	 * @return a selector that chooses the Attribute Consuming Service with the
	 *         given name; please note that this selector will select the default
	 *         service if no one is found with the given name
	 */
	static AttributeConsumingServiceSelector byServiceName(final Saml2Settings settings, final String serviceName) {
		return () -> {
			final List<AttributeConsumingService> services = settings.getSpAttributeConsumingServices();
			if (services != null)
				return services.stream().filter(service -> service.getServiceName().equals(serviceName))
				            .findFirst().map(AttributeConsumingService::getIndex).orElse(null);
			else
				return null;
		};
	}

	/**
	 * Returns the index of the selected Attribute Consuming Service.
	 * 
	 * @return the service index, or <code>null</code> if the default one should be selected
	 */
	Integer getAttributeConsumingServiceIndex();
}