using FundooModel.Notes;
using FundooRepository.Context;
using FundooRepository.IRepository;
using NlogImplementation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FundooRepository.Repository
{
    public class CollaboratorRepository : ICollaboratorRepository
    {
        public readonly UserDbContext context;
        NlogOperation nlog = new NlogOperation();
        public CollaboratorRepository(UserDbContext context)
        {
            this.context = context;
        }

        public Task<int> AddCollaborator(Collaborator collaborator)
        {
            this.context.Collaborator.Add(collaborator);
            var result = this.context.SaveChangesAsync();
            nlog.LogInfo("Collaborator added");
            return result;
        }

        public bool DeleteCollab(int noteId, int receiverId)
        {
            var result = this.context.Collaborator.Where(x => x.NoteId == noteId && x.ReceiverUserId == receiverId).FirstOrDefault();
            if (result != null)
            {



                this.context.Collaborator.Remove(result);
                var deleteResult = this.context.SaveChanges();
                if (deleteResult == 1)
                {
                    nlog.LogInfo("Collaborator deleted added");
                    return true;
                }
            }
            nlog.LogWarn("Collaborator not found");
            return false;
        }

        public IEnumerable<Collaborator> GetAllCollabNotes(int userId, string labelId)
        {
            var result = this.context.Collaborator.Where(x => x.SenderUserId == userId || x.ReceiverUserId == userId).AsEnumerable();
            if (result != null)
            {
                nlog.LogInfo("Got all notes with Collabrator added");
                return result;
            }
            nlog.LogWarn("Collaborator with notes not found");
            return null;
        }

        public IEnumerable<NotesCollab> GetAllNotesColllab(int userId)
        {
            List<NotesCollab> collab = new List<NotesCollab>();
            var result = this.context.Notes.Join(this.context.Collaborator.Where(X=> X.SenderUserId ==  userId),
                Note => Note.NoteId,
                Collaborator => Collaborator.NoteId,
                (Note, Collaborator) => new NotesCollab
                {
                    NoteId = Note.NoteId,
                    Title = Note.Title,
                    Description = Note.Description,
                    Image = Note.Image,
                    Colour = Note.Color,
                    Reminder = Note.Remainder,
                    IsArchive = Note.IsArchive,
                    IsPin = Note.IsPin,
                    IsTrash = Note.IsTrash,
                    CreatedDate = Note.CreatedDate,
                    CollabId = Collaborator.CollabId,
                    SenderUserId =Collaborator.SenderUserId,
                    ReceiverUserId = Collaborator.ReceiverUserId                    
                });
            foreach (var data in result)
            {
                if (data.SenderUserId == userId || data.ReceiverUserId == userId)
                {
                    collab.Add(data);
                }
            }
            nlog.LogInfo("Dispalyed All Collab Notes Successfully");
            return result;
        }


    }
}
