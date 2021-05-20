package com.grifell.pep;

import javax.annotation.security.RunAs;
import javax.ejb.LocalBean;
import javax.ejb.Schedule;
import javax.ejb.Singleton;
import javax.ejb.Startup;

@Singleton
@LocalBean
@Startup
@RunAs("SYSTEM")
public class BatchManagerBean {

    @Schedule(dayOfWeek = "*", hour = "0", persistent = false)
    public void cleanTimeout() {
        //calls a securized EJB
    }

}
