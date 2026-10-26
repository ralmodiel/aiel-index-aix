var app = builder.Build();
var v1 = app.MapGroup("/api/v1");
app.MapGet("/health", () => "ok");
v1.MapPost("/items", ItemHandlers.Create).RequireAuthorization("Admin");
v1.MapGet("/items/{id}", GetItem).AllowAnonymous();
static IResult GetItem(int id) => Results.Ok();
