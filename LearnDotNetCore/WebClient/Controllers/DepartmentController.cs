using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using LearnDotNetCore.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace WebClient.Controllers
{
    public class DepartmentController : Controller
    {
        public HttpClient http = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:44316/api/")
        };

        public IActionResult Index()
        {
            if (HttpContext.Session.GetString("lvl") == "Admin")
            {
                return View("~/Views/Department/Index.cshtml");
            }
            return Redirect("/notfound");
        }

        public JsonResult LoadDepart()
        {
            IEnumerable<Department> departments = null;
            var token = HttpContext.Session.GetString("token");             //tambahan
            http.DefaultRequestHeaders.Add("Authorization", token);         //tambahan
            var resTask = http.GetAsync("Departments");
            resTask.Wait();

            var result = resTask.Result;
            if (result.IsSuccessStatusCode)
            {
                var readTask = result.Content.ReadAsAsync<List<Department>>();
                readTask.Wait();
                departments = readTask.Result;
            }
            else                                                            //tambahan
            {
                departments = Enumerable.Empty<Department>();
                ModelState.AddModelError(string.Empty, "Server Error try after sometimes.");
            }

            return Json(departments);
        }

        public JsonResult GetById(int id)
        {
            Department departments = null;
            var token = HttpContext.Session.GetString("token");             //tambahan
            http.DefaultRequestHeaders.Add("Authorization", token);         //tambahan
            var resTask = http.GetAsync("departments/" + id);
            resTask.Wait();

            var result = resTask.Result;
            if (result.IsSuccessStatusCode)
            {
                var getJson = JsonConvert.DeserializeObject(result.Content.ReadAsStringAsync().Result).ToString();
                departments = JsonConvert.DeserializeObject<Department>(getJson);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Server Error try after sometimes.");
            }

            return Json(departments);
        }

        public JsonResult InsertOrUpdate(Department departments, int id)
        {
            try
            {
                var json = JsonConvert.SerializeObject(departments);
                var buffer = System.Text.Encoding.UTF8.GetBytes(json);
                var byteContent = new ByteArrayContent(buffer);
                byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

                var token = HttpContext.Session.GetString("token");                 //tambahan
                http.DefaultRequestHeaders.Add("Authorization", token);             //tambahan
                if (departments.Id == 0)
                {
                    var result = http.PostAsync("departments", byteContent).Result;
                    return Json(result);
                }
                else if (departments.Id != 0)
                {
                    var result = http.PutAsync("departments/" + id, byteContent).Result;
                    return Json(result);
                }

                return Json(404);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public JsonResult Delete(int id)
        {
            var token = HttpContext.Session.GetString("token");                     //tambahan
            http.DefaultRequestHeaders.Add("Authorization", token);                 //tambahan
            var result = http.DeleteAsync("departments/" + id).Result;
            return Json(result);
        }
    }
}