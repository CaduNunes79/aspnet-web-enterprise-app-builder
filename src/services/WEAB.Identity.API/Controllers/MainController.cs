using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace WEAB.Identity.API.Controllers
{
    [ApiController]
    public abstract class MainController : Controller
    {
        protected ICollection<string> Errors = new List<string>();

        protected ActionResult CustomReponse(object result = null)
        {
            if (OperationIsValid())
            {
                return Ok(result);
            }

            return BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                {"Messages", Errors.ToArray()}
            }));

        }

        protected ActionResult CustomResponse(ModelStateDictionary modelState)
        {
            var errors = modelState.Values.SelectMany(e => e.Errors);
            foreach (var error in errors)
            {
                AddProccessError(error.ErrorMessage);
            }

            return CustomReponse();
        }

        protected bool OperationIsValid()
        {
            return !Errors.Any();
        }

        protected void AddProccessError(string error)
        {
            Errors.Add(error);
        }

        protected void ClearProccessError()
        {
            Errors.Clear();
        }
    }
}
