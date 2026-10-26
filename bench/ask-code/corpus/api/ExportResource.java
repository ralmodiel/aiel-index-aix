package demo.api;

public class ExportResource {
    /** Download a table as CSV with a footer marking the copy as not official. */
    public Response exportCsv(String table) {
        StringBuilder sb = new StringBuilder(rowsAsCsv(table));
        sb.append("\n# UNOFFICIAL COPY - not valid for submission\n");
        return Response.ok(sb.toString()).type("text/csv").build();
    }
}
