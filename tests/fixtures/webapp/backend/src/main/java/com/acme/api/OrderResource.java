package com.acme.api;

import com.acme.security.Roles;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.*;

@Path("/api/orders")
@RolesAllowed({Roles.CLERK, Roles.ADMIN, Roles.MANAGER})
public class OrderResource {
    public static final String FEATURE_REFUNDS = "refunds";

    @GET
    public String list(@QueryParam("status") String status) {
        return "[]";
    }

    @POST
    @Path("/{id}/cancel")
    public String cancel(@PathParam("id") String id, String reason) {
        // NOTE: no email is sent here yet
        return id;
    }

    @DELETE
    @Path("/{id}")
    @RolesAllowed({Roles.ADMIN})
    public void remove(@PathParam("id") String id) {
    }

    private void audit(String id) {
    }
}
