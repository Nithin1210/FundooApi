using FundooModel.Notes;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
namespace FundooRepository.IRepository
{
    public interface INotesRepository
    {
        public Task<int> AddNotes(Note note);
        public Note EditNotes(Note note);
        public IEnumerable<Note> GetAllNotes(int userId);
        public bool DeleteNote(int noteid, int userId);
        public IEnumerable<Note> GetArcheived(int userId);
        public IEnumerable<Note> GetPinnedTask(int userId);
        public IEnumerable<Note> GetThrashedTask(int userId);
        public bool TrashNote(int userId);
        public Note ArcheiveNote(int noteId, int userId);
        public Note PinNote(int noteId, int userId);
 
        public bool RestoreNotes(int noteId, int userId);
        public string Image(IFormFile file, int noteId);
        public Note CreateNotesCopy(int userId, int NoteId);

    }
}
