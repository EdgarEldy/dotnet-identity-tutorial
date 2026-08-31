using DotnetIdentityTutorial.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DotnetIdentityTutorial.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens");

        builder.HasKey(rt => rt.Id);

        // SHA-256 hex-encoded is always exactly 64 characters.
        builder.Property(rt => rt.TokenHash)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(rt => rt.SecurityStampAtIssuance)
            .IsRequired();

        // Looked up on every refresh request (RefreshAsync hashes the incoming raw token and
        // finds the matching row by TokenHash) - this is the hot path for the whole rotation
        // mechanism, so it needs an index, not a table scan. Unique because a hash collision
        // producing two live rows would be a correctness bug, not just a performance one.
        builder.HasIndex(rt => rt.TokenHash)
            .IsUnique();

        // Looked up whenever an entire family needs to be revoked at once: reuse detection
        // (RefreshAsync) and a SecurityStamp mismatch both revoke every row sharing a FamilyId.
        builder.HasIndex(rt => rt.FamilyId);

        // Self-referencing: the token a given row was rotated into. SetNull rather than Cascade
        // or Restrict - if the successor row is ever removed by ExpiredTokenCleanupService
        // before this one is, this row simply loses its "replaced by" pointer instead of
        // blocking the delete or cascading into an unrelated row.
        builder.HasOne<RefreshToken>()
            .WithMany()
            .HasForeignKey(rt => rt.ReplacedByTokenId)
            .OnDelete(DeleteBehavior.SetNull);
    }
}
