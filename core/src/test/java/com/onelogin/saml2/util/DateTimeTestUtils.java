package com.onelogin.saml2.util;

import java.time.Clock;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public class DateTimeTestUtils {

    /**
     * Use system clock as "now".
     */
    public static void setCurrentMillisSystem() {
        Util.setSystemClock();
    }

    /**
     * Use provided dateTime as "now".
     * 
     * @param dateTime the timestamp
     */
    public static void setFixedDateTime(String dateTime) {
        Util.setFixedClock(Clock.fixed(ZonedDateTime.parse(dateTime).toInstant(), ZoneOffset.UTC));
    }
}
