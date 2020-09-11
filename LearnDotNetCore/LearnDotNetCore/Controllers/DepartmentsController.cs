using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using LearnDotNetCore.Bases;
using LearnDotNetCore.Model;
using LearnDotNetCore.Repositories.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace LearnDotNetCore.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    [Route("api/[controller]")]
    [ApiController]
    public class DepartmentsController : BaseController<Department, DeparmentRepo>
    {
        private readonly DeparmentRepo _repo;

        public DepartmentsController(DeparmentRepo deparmentRepo) : base(deparmentRepo)
        {
            this._repo = deparmentRepo;
        }

        [HttpPut("{Id}")]
        public async Task<ActionResult<int>> Update(int Id, Department entity)
        {
            var getId = await _repo.GetById(Id);
            getId.Name = entity.Name;
            var data = await _repo.Update(getId);
            if (data.Equals(null))
            {
                return BadRequest("Data is not Updated");
            }
            return Ok("Data was updated");
        }
    }
}