package com.onelogin.saml2.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

/**
 * Utility for splitting raw url a raw url query string
 * (foo=bar&hello=world&data=Hi%20there) into
 *
 */
public final class QueryStringSplitter {

	// Group 1 contains key & value, group 2 contains key only
	private static final Pattern RE_QUERY = Pattern.compile("(([^=&]+)(?:=[^&]*)?)(?:&|$)");

	private QueryStringSplitter() {
		// static methods only, no instance
	}

	/**
	 * Splits a raw url query string into a map where:
	 * <ul>
	 * <li>the key is the parameter name
	 * <li>the value is the key & value
	 * </ul>
	 * <b>Note:</b> For keys with multiple values, the first value is used.
	 * <p>
	 * Given the string "foo=bar&hello=world&empty&blank=&data=Hi%20there" it
	 * will return the map:
	 * <ul>
	 * <li>foo: foo=bar
	 * <li>hello: hello=world
	 * <li>empty: empty
	 * <li>blank: blank=
	 * <li>data: data=Hi%20there
	 * </ul>
	 * 
	 * @param queryString
	 *            raw url query string
	 * 
	 * @returns Unmodifiable map, empty if input is empty or null
	 */
	public static Map<String, String> split(final String queryString) {
		if (StringUtils.isBlank(queryString)) {
			return Collections.emptyMap();
		}

		Map<String, String> results = new LinkedHashMap<>();
		Matcher matcher = RE_QUERY.matcher(queryString);
		while (matcher.find()) {
			String key = matcher.group(2);
			if (!results.containsKey(key)) {
				results.put(key, matcher.group(1));
			}
		}

		return Collections.unmodifiableMap(results);
	}

}
