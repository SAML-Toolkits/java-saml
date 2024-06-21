package com.onelogin.saml2.authn;

import java.net.URL;

import com.onelogin.saml2.model.AssertionConsumerService;
import com.onelogin.saml2.settings.Saml2Settings;

/**
 * Interfaced used to select the Assertion Consumer Service (ACS) to be
 * specified in an authentication request. An instance of this interface can be
 * passed as an input parameter in a {@link AuthnRequestParams} to be used when
 * initiating a login operation.
 * <p>
 * A set of predefined implementations are provided: they should cover the most
 * common cases.
 */
@FunctionalInterface
public interface AssertionConsumerServiceSelector {

	/**
	 * Simple class holding data used to select an Assertion Consumer Service (ACS)
	 * within an authentication request.
	 * <p>
	 * The index, if specified, has priority over the pair URL/protocol binding.
	 */
	static class AssertionConsumerServiceSelection {
		/** Assertion Consumer Service index. */
		public final Integer index;
		/** Assertion Consumer Service URL. */
		public final URL url;
		/** Assertion Consumer Service protocol binding. */
		public final String protocolBinding;

		/**
		 * Creates an Assertion Consumer Service selection by index.
		 * 
		 * @param index
		 *              the ACS index
		 */
		public AssertionConsumerServiceSelection(final int index) {
			this.index = index;
			this.url = null;
			this.protocolBinding = null;
		}

		/**
		 * Creates an Assertion Consumer Service selection by URL and protocol binding.
		 * 
		 * @param url
		 *              the ACS URL
		 * @param protocolBinding
		 *              the ACS protocol binding
		 */
		public AssertionConsumerServiceSelection(final URL url, final String protocolBinding) {
			this.index = null;
			this.url = url;
			this.protocolBinding = protocolBinding;
		}
	}

	/**
	 * @return a selector that will cause the authentication request not to specify
	 *         any Assertion Consumer Service, letting the IdP determine which is
	 *         the default one; if the agreement between the SP and the IdP to map
	 *         Assertion Consumer Services is based on metadata, it means that the
	 *         IdP is expected to select the ACS marked there as being the default
	 *         one (or the only declared ACS, if just one exists and hopefully not
	 *         explicitly set as <strong>not</strong> being the default one...);
	 *         indeed, in sane cases the final selection result is expected to be
	 *         the same the one provided by
	 *         {@link AssertionConsumerServiceSelector#useDefaultByIndex(Saml2Settings)}
	 *         and
	 *         {@link AssertionConsumerServiceSelector#useDefaultByUrlAndBinding(Saml2Settings)},
	 *         with those two however causing an explicit indication of the choice
	 *         being made by the SP in the authentication request, indication that
	 *         the IdP must then respect
	 */
	static AssertionConsumerServiceSelector useImplicitDefault() {
		return () -> null;
	}

	/**
	 * @param settings
	 *              the SAML settings, containing the list of the available
	 *              Assertion Consumer Services (see
	 *              {@link Saml2Settings#getSpAssertionConsumerServices()})
	 * @return a selector that will cause the authentication request to explicitly
	 *         specify the default Assertion Consumer Service declared in a set of
	 *         SAML settings, selecting it by index; if no default ACS could be
	 *         unambiguously detected, this falls back to
	 *         {@link #useImplicitDefault()}
	 * @see Saml2Settings#getSpAssertionConsumerServices()
	 * @see Saml2Settings#getSpDefaultAssertionConsumerService()
	 */
	static AssertionConsumerServiceSelector useDefaultByIndex(final Saml2Settings settings) {
		return settings.getSpDefaultAssertionConsumerService().map(AssertionConsumerServiceSelector::byIndex)
		            .orElse(useImplicitDefault());
	}

	/**
	 * @param settings
	 *              the SAML settings, containing the list of the available
	 *              Assertion Consumer Services (see
	 *              {@link Saml2Settings#getSpAssertionConsumerServices()})
	 * @return a selector that will cause the authentication request to explicitly
	 *         specify the default Assertion Consumer Service declared in a set of
	 *         SAML settings, selecting it by URL and protocol binding; if no
	 *         default ACS could be unambiguously detected, this falls back to
	 *         {@link #useImplicitDefault()}
	 * @see Saml2Settings#getSpAssertionConsumerServices()
	 * @see Saml2Settings#getSpDefaultAssertionConsumerService()
	 */
	static AssertionConsumerServiceSelector useDefaultByUrlAndBinding(final Saml2Settings settings) {
		return settings.getSpDefaultAssertionConsumerService().map(AssertionConsumerServiceSelector::byUrlAndBinding)
		            .orElse(useImplicitDefault());
	}

	/**
	 * @param assertionConsumerService
	 *              the Assertion Consumer Service to select
	 * @return a selector that chooses the specified Assertion Consumer Service by
	 *         index
	 */
	static AssertionConsumerServiceSelector byIndex(final AssertionConsumerService assertionConsumerService) {
		return byIndex(assertionConsumerService.getIndex());
	}

	/**
	 * @param assertionConsumerService
	 *              the Assertion Consumer Service to select
	 * @return a selector that chooses the specified Assertion Consumer Service by
	 *         location URL and protocol binding
	 */
	static AssertionConsumerServiceSelector byUrlAndBinding(final AssertionConsumerService assertionConsumerService) {
		return () -> new AssertionConsumerServiceSelection(assertionConsumerService.getLocation(),
		            assertionConsumerService.getBinding());
	}

	/**
	 * @param index
	 *              the index of the Assertion Consumer Service to select
	 * @return a selector that chooses the Assertion Consumer Service with the given
	 *         index
	 */
	static AssertionConsumerServiceSelector byIndex(final int index) {
		return () -> new AssertionConsumerServiceSelection(index);
	}

	/**
	 * @param url
	 *              the URL of the Assertion Consumer Service to select
	 * @param protocolBinding
	 *              the protocol binding of the Assertion Consumer Service to select
	 * @return a selector that chooses the Assertion Consumer Service with the given
	 *         URL and protocol binding
	 */
	static AssertionConsumerServiceSelector byUrlAndBinding(final URL url, final String protocolBinding) {
		return () -> new AssertionConsumerServiceSelection(url, protocolBinding);
	}

	/**
	 * Returns a description of the selected Assertion Consumer Service.
	 * 
	 * @return the service index, or <code>null</code> if the default one should be
	 *         selected
	 */
	AssertionConsumerServiceSelection getAssertionConsumerServiceSelection();
}