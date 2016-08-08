package com.onelogin.saml2.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.onelogin.saml2.test.settings.SettingBuilderTest;
import com.onelogin.saml2.test.util.UtilsTest;

@RunWith(Suite.class)
@SuiteClasses({ UtilsTest.class, SettingBuilderTest.class })
public class AllTestsSuite {

}