using DotnetIdentityTutorial.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DotnetIdentityTutorial.Data.Configurations;

public class PermissionConfiguration : IEntityTypeConfiguration<Permission>
{
    public void Configure(EntityTypeBuilder<Permission> builder)
    {
        builder.ToTable("Permissions");

        builder.HasKey(p => p.Id);

        builder.Property(p => p.Resource)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(p => p.Action)
            .IsRequired()
            .HasMaxLength(100);

        // Seeding is check-then-insert (see DbInitializer), but this index is still the
        // real idempotency guarantee at the schema level: a race between two startups
        // (or a manual insert) can never produce a duplicate USER:READ row.
        builder.HasIndex(p => new { p.Resource, p.Action })
            .IsUnique();
    }
}
