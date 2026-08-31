using DotnetIdentityTutorial.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace DotnetIdentityTutorial.Data.Configurations;

public class BlacklistedAccessTokenConfiguration : IEntityTypeConfiguration<BlacklistedAccessToken>
{
    public void Configure(EntityTypeBuilder<BlacklistedAccessToken> builder)
    {
        builder.ToTable("BlacklistedAccessTokens");

        builder.HasKey(b => b.Id);

        builder.Property(b => b.Jti)
            .IsRequired()
            .HasMaxLength(64);

        // Looked up on every authenticated request (JwtBearerEvents.OnTokenValidated in
        // Program.cs), so this needs to be fast, not a table scan. Unique because the same jti
        // must never be blacklisted twice - RevokeAsync's check-then-insert already avoids the
        // attempt, this is the schema-level guarantee behind that, the same pattern
        // PermissionConfiguration uses for (Resource, Action).
        builder.HasIndex(b => b.Jti)
            .IsUnique();
    }
}
