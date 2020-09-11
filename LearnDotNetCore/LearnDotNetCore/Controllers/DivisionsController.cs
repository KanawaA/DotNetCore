using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LearnDotNetCore.Bases;
using LearnDotNetCore.Models;
using LearnDotNetCore.Repositories.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace LearnDotNetCore.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    [Route("api/[controller]")]
    [ApiController]
    public class DivisionsController : BaseController<Division, DivisionRepo>
    {
        private readonly DivisionRepo _repo;

        public DivisionsController(DivisionRepo divisionRepo) : base(divisionRepo)
        {
            this._repo = divisionRepo;
        }

        [HttpPut("{Id}")]
        public async Task<ActionResult<int>> Update(int Id, Division division)
        {
            var getId = await _repo.GetById(Id);
            getId.Name = division.Name;
            getId.DepartmentId = division.DepartmentId;
            var data = await _repo.Update(getId);
            if (data.Equals(null))
            {
                return BadRequest("Data is not Updated");
            }
            return Ok("Data was updated");
        }
    }
}