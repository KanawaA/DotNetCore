#pragma checksum "C:\1 File Kanawa\Bootcamp MII\Project\DotNetCore\LearnDotNetCore\WebClient\Views\Dashboard\Index.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "ba99db0d8d94d8b7cb18d7f8c28bcbe827ae1dc1"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Dashboard_Index), @"mvc.1.0.view", @"/Views/Dashboard/Index.cshtml")]
[assembly:global::Microsoft.AspNetCore.Mvc.Razor.Compilation.RazorViewAttribute(@"/Views/Dashboard/Index.cshtml", typeof(AspNetCore.Views_Dashboard_Index))]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#line 1 "C:\1 File Kanawa\Bootcamp MII\Project\DotNetCore\LearnDotNetCore\WebClient\Views\_ViewImports.cshtml"
using Web;

#line default
#line hidden
#line 2 "C:\1 File Kanawa\Bootcamp MII\Project\DotNetCore\LearnDotNetCore\WebClient\Views\_ViewImports.cshtml"
using Web.Models;

#line default
#line hidden
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"ba99db0d8d94d8b7cb18d7f8c28bcbe827ae1dc1", @"/Views/Dashboard/Index.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"243bef8901b38e9eef9e38f8c66b8f401f171c9b", @"/Views/_ViewImports.cshtml")]
    public class Views_Dashboard_Index : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<dynamic>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("src", new global::Microsoft.AspNetCore.Html.HtmlString("~/js/Script/Dashboard.js"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            BeginContext(0, 2, true);
            WriteLiteral("\r\n");
            EndContext();
#line 2 "C:\1 File Kanawa\Bootcamp MII\Project\DotNetCore\LearnDotNetCore\WebClient\Views\Dashboard\Index.cshtml"
   ViewData["Title"] = "Index";
    Layout = "~/Views/Layout/_Layout.cshtml"; 

#line default
#line hidden
            BeginContext(84, 4700, true);
            WriteLiteral(@"<!-- Content Row -->
<div class=""row"">
    <!-- Earnings (Monthly) Card Example -->
    <div class=""col-xl-3 col-md-6 mb-4"">
        <div class=""card border-left-primary shadow h-100 py-2"">
            <div class=""card-body"">
                <div class=""row no-gutters align-items-center"">
                    <div class=""col mr-2"">
                        <div class=""text-xs font-weight-bold text-primary text-uppercase mb-1"">Earnings (Monthly)</div>
                        <div class=""h5 mb-0 font-weight-bold text-gray-800"">$40,000</div>
                    </div>
                    <div class=""col-auto"">
                        <i class=""fas fa-calendar fa-2x text-gray-300""></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Earnings (Monthly) Card Example -->
    <div class=""col-xl-3 col-md-6 mb-4"">
        <div class=""card border-left-success shadow h-100 py-2"">
            <div class=""card-body"">
                <div class=""row");
            WriteLiteral(@" no-gutters align-items-center"">
                    <div class=""col mr-2"">
                        <div class=""text-xs font-weight-bold text-success text-uppercase mb-1"">Earnings (Annual)</div>
                        <div class=""h5 mb-0 font-weight-bold text-gray-800"">$215,000</div>
                    </div>
                    <div class=""col-auto"">
                        <i class=""fas fa-dollar-sign fa-2x text-gray-300""></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Earnings (Monthly) Card Example -->
    <div class=""col-xl-3 col-md-6 mb-4"">
        <div class=""card border-left-info shadow h-100 py-2"">
            <div class=""card-body"">
                <div class=""row no-gutters align-items-center"">
                    <div class=""col mr-2"">
                        <div class=""text-xs font-weight-bold text-info text-uppercase mb-1"">Tasks</div>
                        <div class=""row no-gutters align-items-center"">
       ");
            WriteLiteral(@"                     <div class=""col-auto"">
                                <div class=""h5 mb-0 mr-3 font-weight-bold text-gray-800"">50%</div>
                            </div>
                            <div class=""col"">
                                <div class=""progress progress-sm mr-2"">
                                    <div class=""progress-bar bg-info"" role=""progressbar"" style=""width: 50%"" aria-valuenow=""50"" aria-valuemin=""0"" aria-valuemax=""100""></div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class=""col-auto"">
                        <i class=""fas fa-clipboard-list fa-2x text-gray-300""></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Pending Requests Card Example -->
    <div class=""col-xl-3 col-md-6 mb-4"">
        <div class=""card border-left-warning shadow h-100 py-2"">
            <div class=""card-body"">");
            WriteLiteral(@"
                <div class=""row no-gutters align-items-center"">
                    <div class=""col mr-2"">
                        <div class=""text-xs font-weight-bold text-warning text-uppercase mb-1"">Pending Requests</div>
                        <div class=""h5 mb-0 font-weight-bold text-gray-800"">18</div>
                    </div>
                    <div class=""col-auto"">
                        <i class=""fas fa-comments fa-2x text-gray-300""></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<div class=""row"">
    <!-- Donut Chart -->
    <div class=""col-lg-6"">
        <div class=""card "">
            <!-- Card Header - Dropdown -->
            <div class=""card-header "">
                <h6 class=""m-0 font-weight-bold text-primary"">Donut Chart</h6>
            </div>
            <!-- Card Body -->
            <div class=""card-body"">
                <div class=""col-md-12"">
                    <div class=""amChart"" id=""pieChart""");
            WriteLiteral(@"></div>
                </div>
            </div>
        </div>
    </div>
    <!-- Donut Chart -->
    <div class=""col-lg-6"">
        <div class=""card "">
            <!-- Card Header - Dropdown -->
            <div class=""card-header "">
                <h6 class=""m-0 font-weight-bold text-primary"">Bar Chart</h6>
            </div>
            <!-- Card Body -->
            <div class=""card-body"">
                <div class=""col-md-12"">
                    <div class=""amChart"" id=""barChart""></div>
                </div>
            </div>
        </div>
    </div>

</div>

");
            EndContext();
            DefineSection("Scripts", async() => {
                BeginContext(4801, 6, true);
                WriteLiteral("\r\n    ");
                EndContext();
                BeginContext(4807, 48, false);
                __tagHelperExecutionContext = __tagHelperScopeManager.Begin("script", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "c874d91479de432b8002647890669e62", async() => {
                }
                );
                __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.UrlResolutionTagHelper>();
                __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_UrlResolutionTagHelper);
                __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
                await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
                if (!__tagHelperExecutionContext.Output.IsContentModified)
                {
                    await __tagHelperExecutionContext.SetOutputContentAsync();
                }
                Write(__tagHelperExecutionContext.Output);
                __tagHelperExecutionContext = __tagHelperScopeManager.End();
                EndContext();
                BeginContext(4855, 2, true);
                WriteLiteral("\r\n");
                EndContext();
            }
            );
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<dynamic> Html { get; private set; }
    }
}
#pragma warning restore 1591
