using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using LearnDotNetCore.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace WebClient.Controllers
{
    public class DivisionController : Controller
    {
        public HttpClient client = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:44316/api/")
        };

        public IActionResult Index()
        {
            if (HttpContext.Session.GetString("lvl") == "Admin")
            {
                return View("~/Views/Division/Index.cshtml");
            }
            return Redirect("/notfound");
        }

        public JsonResult LoadDiv()
        {
            IEnumerable<Division> divisions = null;
            var token = HttpContext.Session.GetString("token");             //tambahan
            client.DefaultRequestHeaders.Add("Authorization", token);         //tambahan
            var resTask = client.GetAsync("Divisions");
            resTask.Wait();

            var result = resTask.Result;
            if (result.IsSuccessStatusCode)
            {
                var readTask = result.Content.ReadAsAsync<List<Division>>();
                readTask.Wait();
                divisions = readTask.Result;
            }
            else                                                            //tambahan
            {
                divisions = Enumerable.Empty<Division>();
                ModelState.AddModelError(string.Empty, "Server Error try after sometimes.");
            }

            return Json(divisions);
        }

        public JsonResult GetById(int id)
        {
            Division divisions = null;
            var token = HttpContext.Session.GetString("token");             //tambahan
            client.DefaultRequestHeaders.Add("Authorization", token);         //tambahan
            var resTask = client.GetAsync("divisions/" + id);
            resTask.Wait();

            var result = resTask.Result;
            if (result.IsSuccessStatusCode)
            {
                var getJson = JsonConvert.DeserializeObject(result.Content.ReadAsStringAsync().Result).ToString();
                divisions = JsonConvert.DeserializeObject<Division>(getJson);
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Server Error try after sometimes.");
            }

            return Json(divisions);
        }

        public JsonResult InsertOrUpdate(Division divisions, int id)
        {
            try
            {
                var json = JsonConvert.SerializeObject(divisions);
                var buffer = System.Text.Encoding.UTF8.GetBytes(json);
                var byteContent = new ByteArrayContent(buffer);
                byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");

                var token = HttpContext.Session.GetString("token");             //tambahan
                client.DefaultRequestHeaders.Add("Authorization", token);       //tambahan
                if (divisions.Id == 0)
                {
                    var result = client.PostAsync("divisions", byteContent).Result;
                    return Json(result);
                }
                else if (divisions.Id != 0)
                {
                    var result = client.PutAsync("divisions/" + id, byteContent).Result;
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
            var token = HttpContext.Session.GetString("token");                 //tambahan
            client.DefaultRequestHeaders.Add("Authorization", token);           //tambahan
            var result = client.DeleteAsync("divisions/" + id).Result;
            return Json(result);
        }
    }
}