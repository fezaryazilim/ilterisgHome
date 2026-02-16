using System;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ilterisgHome.Migrations
{
    /// <inheritdoc />
    public partial class slugfalan : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MetaDescription",
                table: "blogposts",
                type: "varchar(160)",
                maxLength: 160,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "MetaKeywords",
                table: "blogposts",
                type: "varchar(300)",
                maxLength: 300,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "MetaTitle",
                table: "blogposts",
                type: "varchar(70)",
                maxLength: 70,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "Slug",
                table: "blogposts",
                type: "varchar(220)",
                maxLength: 220,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "FirstName",
                table: "aspnetusers",
                type: "varchar(100)",
                maxLength: 100,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "LastName",
                table: "aspnetusers",
                type: "varchar(100)",
                maxLength: 100,
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateTable(
                name: "blogcomments",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("MySql:ValueGenerationStrategy", MySqlValueGenerationStrategy.IdentityColumn),
                    BlogPostId = table.Column<int>(type: "int", nullable: false),
                    AuthorName = table.Column<string>(type: "varchar(120)", maxLength: 120, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CommentText = table.Column<string>(type: "varchar(2000)", maxLength: 2000, nullable: false)
                        .Annotation("MySql:CharSet", "utf8mb4"),
                    CreatedAt = table.Column<DateTime>(type: "datetime(6)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_blogcomments", x => x.Id);
                    table.ForeignKey(
                        name: "FK_blogcomments_blogposts_BlogPostId",
                        column: x => x.BlogPostId,
                        principalTable: "blogposts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                })
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.CreateIndex(
                name: "IX_blogposts_Slug",
                table: "blogposts",
                column: "Slug");

            migrationBuilder.CreateIndex(
                name: "IX_blogcomments_BlogPostId",
                table: "blogcomments",
                column: "BlogPostId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "blogcomments");

            migrationBuilder.DropIndex(
                name: "IX_blogposts_Slug",
                table: "blogposts");

            migrationBuilder.DropColumn(
                name: "MetaDescription",
                table: "blogposts");

            migrationBuilder.DropColumn(
                name: "MetaKeywords",
                table: "blogposts");

            migrationBuilder.DropColumn(
                name: "MetaTitle",
                table: "blogposts");

            migrationBuilder.DropColumn(
                name: "Slug",
                table: "blogposts");

            migrationBuilder.DropColumn(
                name: "FirstName",
                table: "aspnetusers");

            migrationBuilder.DropColumn(
                name: "LastName",
                table: "aspnetusers");
        }
    }
}
