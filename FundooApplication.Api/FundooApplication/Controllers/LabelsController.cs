using FundooManager.IManager;
using FundooModel.Notes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System;
using FundooModel.Labels;

namespace FundooApplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LabelsController : ControllerBase
    {
        public readonly ILabelsManager labelsManager;
        public LabelsController(ILabelsManager labelsManager)
        {
            this.labelsManager = labelsManager;
        }
        [HttpPost]
        [Route("AddNewLabel")]
        public async Task<ActionResult> AddLabe(label labels)
        {
            try
            {
                var result = await this.labelsManager.AddLabels(labels);
                if (result == 1)
                {
                    return this.Ok(new { Status = true, Message = "Adding Label Successful", data = labels });
                }
                return this.BadRequest(new { Status = false, Message = "Label empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }

        [HttpPut]
        [Route("EditExistingLabels")]
        public ActionResult EditLabel(label labels)
        {
            try
            {
                var result = this.labelsManager.EditLabel(labels);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Edit Label Successful", data = labels });
                }
                return this.BadRequest(new { Status = false, Message = "Label found empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }

        [HttpPut]
        [Route("DeleteLabel")]
        public ActionResult DeleteLabels(int userId)
        {
            try
            {
                var result = this.labelsManager.DeleteLabels(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Deleted label" });
                }
                return this.BadRequest(new { Status = false, Message = "label not found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpGet]
        [Route("GetAllLabel")]
        public async Task<ActionResult> GetAllLabels(int userId)
        {
            try
            {
                var result = this.labelsManager.GetAllLabels(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "labels displayed", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "No labels Found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }

        [HttpGet]
        [Route("GetAllLabelNotes")]
        public async Task<ActionResult> GetAllLabelNotes(int userId)
        {
            try
            {
                var result = this.labelsManager.GetAllLabelNotes(userId);

                return this.Ok(new { Status = true, Message = "labels displayed", data = result });

            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
    }
}
