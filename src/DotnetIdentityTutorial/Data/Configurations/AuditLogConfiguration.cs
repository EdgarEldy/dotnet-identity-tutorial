using DotnetIdentityTutorial.Identity;
using DotnetIdentityTutorial.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DotnetIdentityTutorial.Data.Configurations;

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("AuditLogs");

        builder.HasKey(a => a.Id);

        builder.Property(a => a.Action)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(a => a.EntityType)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(a => a.EntityId)
            .IsRequired()
            .HasMaxLength(100);

        // Native Postgres jsonb rather than a plain text column - see AuditLog's own remarks
        // for why the shape genuinely varies per action.
        builder.Property(a => a.Details)
            .HasColumnType("jsonb");

        // Looked up whenever GET /api/v1/AuditLogs is filtered by actorUserId.
        builder.HasIndex(a => a.ActorUserId);

        // Looked up whenever GET /api/v1/AuditLogs is filtered by entityType.
        builder.HasIndex(a => a.EntityType);

        // SetNull, not Cascade: the audit trail must outlive the account that produced it, so
        // deleting a user leaves their past audit rows in place with a null actor instead of
        // deleting the history of what they once did - see AuditLog's own remarks.
        builder.HasOne<ApplicationUser>()
            .WithMany()
            .HasForeignKey(a => a.ActorUserId)
            .OnDelete(DeleteBehavior.SetNull);
    }
}
