package com.onelogin.saml2.test.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import com.onelogin.saml2.util.QueryStringSplitter;
import com.onelogin.saml2.util.Util;

public class QueryStringSplitterTest {
	
	@Test
	public void itReturnsEmptyWhenGivenNull () {
		Map<String, String> m = QueryStringSplitter.split(null);
		Assert.assertEquals(Collections.emptyMap(), m);
	}
	
	@Test
	public void itReturnsEmptyWhenGivenEmptyString () {
		Map<String, String> m = QueryStringSplitter.split("");
		Assert.assertEquals(Collections.emptyMap(), m);
	}
	
	@Test
	public void itReturnsEmptyWhenGivenBlankString () {
		Map<String, String> m = QueryStringSplitter.split(" ");
		Assert.assertEquals(Collections.emptyMap(), m);
	}
	
	@Test
	public void itSplits_singleKeyCase () {
		String queryString = "foo";
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 1, m.size());
		Assert.assertEquals("foo", m.get("foo"));
	}

	@Test
	public void itSplits_singleKeyWithEqualsSeparator () {
		String queryString = "foo=";
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 1, m.size());
		Assert.assertEquals("foo=", m.get("foo"));
	}

	@Test
	public void itSplits_singleKeyValue () {
		String queryString = "foo=bar";
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 1, m.size());
		Assert.assertEquals("foo=bar", m.get("foo"));
	}
	
	@Test
	public void itSplits_multiValueKey_firstValuePicked () {
		String queryString = "foo=bar&foo=error";
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 1, m.size());
		Assert.assertEquals("foo=bar", m.get("foo"));
	}

	@Test
	public void itSplits_multipleKeyValue () {
		String queryString = "foo=bar&hello=world";
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 2, m.size());
		Assert.assertEquals("foo=bar", m.get("foo"));
		Assert.assertEquals("hello=world", m.get("hello"));
	}

	@Test
	public void itSplits_multipleForms () {
		String queryString = "foo=bar&hello=world&empty&keyAndEquals=";
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 4, m.size());
		Assert.assertEquals("foo=bar", m.get("foo"));
		Assert.assertEquals("hello=world", m.get("hello"));
		Assert.assertEquals("empty", m.get("empty"));
		Assert.assertEquals("keyAndEquals=", m.get("keyAndEquals"));
	}
	
	@Test
	public void itSplits_realUrlEncodedCase () {
		String foo = "foo=" + Util.urlEncoder("I am complex!");
		String bar = "bar=" + Util.urlEncoder("%100 disaster & chaos");
		String queryString = foo + "&" + bar;
		Map<String, String> m = QueryStringSplitter.split(queryString);
		Assert.assertEquals("Number of results", 2, m.size());
		Assert.assertEquals(foo, m.get("foo"));
		Assert.assertEquals(bar, m.get("bar"));
	}
	
	
	@Test
	public void itReturnsUnmodifiableMap_whenEmpty () {
		Map<String, String> m = QueryStringSplitter.split("");
		assertUnmodifiableMap(m);
	}
	
	@Test
	public void itReturnsUnmodifiableMap_whenNotEmpty () {
		Map<String, String> m = QueryStringSplitter.split("foo=bar");
		assertUnmodifiableMap(m);
	}
	
	public static void assertUnmodifiableMap(Map<?, ?> mapToTest) {
		final Class<?> unmodifiableMapClass = Collections.unmodifiableMap(new HashMap<>()).getClass();

		if (Collections.EMPTY_MAP != mapToTest) {
			Assert.assertSame("Unmodifiable map", unmodifiableMapClass, mapToTest.getClass());
		}
	}
}
