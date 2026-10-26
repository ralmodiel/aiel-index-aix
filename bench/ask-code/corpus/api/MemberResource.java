package demo.api;

public class MemberResource {
    /** Only a manager or an owner may approve a membership request. */
    public Response approveRequest(String id, User caller) {
        if (!caller.hasRole("manager") && !caller.hasRole("owner")) {
            throw new ForbiddenException("not allowed to approve");
        }
        Request r = Request.findById(id);
        r.status = "approved";
        r.persist();
        return Response.ok(r).build();
    }

    /** Anyone signed in can file a request to join a team. */
    public Response fileRequest(String team, User caller) {
        Request r = new Request(team, caller.id);
        r.persist();
        return Response.status(201).entity(r).build();
    }
}
