package com.acme.api;

import jakarta.annotation.security.PermitAll;
import jakarta.ws.rs.*;

@Path("/api/reports")
public class ReportResource {
    @GET
    @Path("/monthly")
    @PermitAll
    public String monthly() {
        return "{}";
    }
}
