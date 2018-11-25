/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.chikelueoji.tracerouteplus;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author CHIKEO
 */
public class TraceroutePlusJUnit4Test {
    
    public TraceroutePlusJUnit4Test() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }


    /**
     * Test of getInterfaceList method, of class TraceroutePlus.
     * There must be at least one network interface.
     */
    @Test
    public void testInterfaceExists() {
        System.out.println("getInterfaceList");
        TraceroutePlus instance = new TraceroutePlus();
        String[] result = instance.getInterfaceList();
        assertTrue(result.length > 0);
    }

}
