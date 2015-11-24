package com.onelogin.saml2;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class ConsoleTestRunner {
	public static void main(String[] args) {
		Result result = JUnitCore.runClasses(AllTestsSuite.class);
		for (Failure failure : result.getFailures()) {
			System.out.println(failure.toString());
		}
	}
}
