using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NetCoreTokenBasedApproach.Data.Helpers;

namespace NetCoreTokenBasedApproach.Controllers
{
    [Authorize(Roles = UserRoles.Student)]
    [Route("api/[controller]")]
    [ApiController]
    public class StudentController : ControllerBase
    {
        public StudentController()
        {
            
        }

        [HttpGet]
        public IActionResult Get()
        {
            return Ok("done student");
        }
    }
}
