using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NetCoreTokenBasedApproach.Data.Helpers;

namespace NetCoreTokenBasedApproach.Controllers
{
    [Authorize(Roles = UserRoles.Manager)]
    [Route("api/[controller]")]
    [ApiController]
    public class ManagerController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("done manager");
        }
    }
}
