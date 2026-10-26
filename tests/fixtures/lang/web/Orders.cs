using Microsoft.AspNetCore.Mvc;
namespace Shop.Api;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin,Clerk")]
public class OrdersController : ControllerBase
{
    [HttpGet]
    public IActionResult List() => Ok();

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id) { return Ok(); }

    [AllowAnonymous]
    [HttpPost("submit")]
    public IActionResult Submit([FromBody] Order o) => Ok();

    [HttpDelete("~/api/legacy/{id}")]
    public IActionResult Remove(int id) => Ok();
}
