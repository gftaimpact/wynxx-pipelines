package com.scalesec.vulnado;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
	@SpringBootTest
	public class VulnadoApplicationTests {

    @Autowired
    private ApplicationContext applicationContext;

    }
        assertNotNull(applicationContext);
    public void contextLoads() {
    @Test