using FundooManager.IManager;
using FundooModel.Notes;
using FundooRepository.IRepository;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
namespace FundooManager.Manager
{
    public class NotesManager : INotesManger
    {
        public readonly INotesRepository NotesRepository;
        public NotesManager(INotesRepository NotesRepository)
        {
            this.NotesRepository = NotesRepository;
        }
        public Task<int> AddNotes(Note note)
        {
            var result = this.NotesRepository.AddNotes(note);
            return result;
        }
        public Note EditNotes(Note note)
        {
            var result = this.NotesRepository.EditNotes(note);
            return result;
        }
        public IEnumerable<Note> GetAllNotes(int userId)
        {
            var result = this.NotesRepository.GetAllNotes(userId);
            return result;
        }
        public bool DeleteNote(int noteid, int userId)
        {
            var result = this.NotesRepository.DeleteNote(noteid, userId);
            return result;
        }
        public IEnumerable<Note> GetArcheived(int userId)
        {
            var result = this.NotesRepository.GetArcheived(userId);
            return result;
        }
        public IEnumerable<Note> GetPinnedTask(int userId)
        {
            var result = this.NotesRepository.GetPinnedTask(userId);
            return result;
        }
        public IEnumerable<Note> GetThrashedTask(int userId)
        {
            var result = this.NotesRepository.GetThrashedTask(userId);
            return result;
        }
        public bool TrashNote(int userId)
        {
            var result = this.NotesRepository.TrashNote(userId);
            return result;
        }
        public Note ArcheiveNote(int noteId, int userId)
        {
            var result = this.NotesRepository.ArcheiveNote(noteId, userId);
            return result;
        }
        public Note PinNote(int noteId, int userId)
        {
            var result = this.NotesRepository.PinNote(noteId, userId);
            return result;
        }
    
        public bool RestoreNotes(int noteId, int userId)
        {
            var result = this.NotesRepository.RestoreNotes(noteId, userId);
            return result;
        }

        public string Image(IFormFile file, int noteId)
        {
            var result = this.NotesRepository.Image(file, noteId);
            return result;
        }
        public Note CreateNotesCopy(int userId, int NoteId)
        {
            var result = this.NotesRepository.CreateNotesCopy(userId, NoteId);
            return result;
        }
    }
}