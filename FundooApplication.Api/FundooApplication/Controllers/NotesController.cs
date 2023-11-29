using FundooManager.IManager;
using FundooModel.User;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System;
using FundooModel.Notes;    
using System.Collections;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;

namespace FundooApplication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class NotesController : ControllerBase
    {
        public readonly INotesManger NoteManager;
        public NotesController(INotesManger NoteManager)
        {
            this.NoteManager = NoteManager;
        }
        [HttpPost]
        [Route("AddNewNote")]
        public async Task<ActionResult> AddNotes(Note note)
        {
            try
            {
                var result = await this.NoteManager.AddNotes(note);
                if (result == 1)
                {
                    return this.Ok(new { Status = true, Message = "Adding Notes Successful", data = note });
                }
                return this.BadRequest(new { Status = false, Message = "Notes empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpPut]
        [Route("EditExistingNote")]
        public ActionResult EditNotes(Note note)
        {
            try
            {
                var result = this.NoteManager.EditNotes(note);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Edit Task Successful", data = note });
                }
                return this.BadRequest(new { Status = false, Message = "Notes found empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpPut]
        [Route("DeleteNote")]
        public ActionResult DeleteNote(int noteid, int userId)
        {
            try
            {
                var result = this.NoteManager.DeleteNote(noteid, userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Moved to Trash" });
                }
                return this.BadRequest(new { Status = false, Message = "Data empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpGet]
        [Route("GetAllNotes")]
        public async Task<ActionResult> GetAllNotes(int userId)
        {
            try
            {
                var result = this.NoteManager.GetAllNotes(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Notes Found", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "No Notes Found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpGet]
        [Route("GetAllArcheivedNotes")]
        public async Task<ActionResult> GetArcheived(int userId)
        {
            try
            {
                var result = this.NoteManager.GetArcheived(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Added to archeived", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "userId data found empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpGet]
        [Route("GetAllPinnedNotes")]
        public async Task<ActionResult> GetPinnedTask(int userId)
        {
            try
            {
                var result = this.NoteManager.GetPinnedTask(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Note Pinned successfully", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "userId not found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpGet]
        [Route("GetAllThrashedNotes")]
        public async Task<ActionResult> GetThrashedTask(int userId)
        {
            try
            {
                var result = this.NoteManager.GetThrashedTask(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Notes Found", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "Null data Found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpDelete]
        [Route("PermanentDeleteNotes")]
        public async Task<ActionResult> TrashNote(int userId)
        {
            try
            {
                var result = this.NoteManager.TrashNote(userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Notes Found" });
                }
                return this.BadRequest(new { Status = false, Message = "No Notes Found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpPut]
        [Route("PutNoteArcheive")]
        public ActionResult ArcheiveNote(int noteid, int userId)
        {
            try
            {
                var result = this.NoteManager.ArcheiveNote(noteid, userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Note Archeived Successful", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "Empty data found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpPut]
        [Route("PutNotePinned")]
        public ActionResult PinNote(int noteid, int userId)
        {
            try
            {
                var result = this.NoteManager.PinNote(noteid, userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Note Pinned Successful", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "Empty data found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }

      

        [HttpPut]
        [Route("RestoreNotes")]
        public ActionResult RestoreNotes(int noteid, int userId)
        {
            try
            {
                var result = this.NoteManager.RestoreNotes(noteid, userId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Note resotored Successful", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "Not found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }


        [HttpPut]
        [Route("Image")]
        public ActionResult Image(IFormFile file, int noteId)
        {
            try
            {
                var result = this.NoteManager.Image(file, noteId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Image Successful", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "No Image found" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }
        [HttpPost]
        [Route("CreateCopyNote")]
        public async Task<ActionResult> CreateNotesCopy(int userId, int NoteId)
        {
            try
            {
                var result = this.NoteManager.CreateNotesCopy(userId, NoteId);
                if (result != null)
                {
                    return this.Ok(new { Status = true, Message = "Adding Notes Successful", data = result });
                }
                return this.BadRequest(new { Status = false, Message = "Notes empty" });
            }
            catch (Exception ex)
            {
                return this.NotFound(new { Status = false, Message = ex.Message });
            }
        }

    }
}
