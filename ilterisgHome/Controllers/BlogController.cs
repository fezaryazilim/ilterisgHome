using Ganss.Xss;
using ilterisg.Data;
using ilterisg.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ilterisg.Controllers
{
    public class BlogController : Controller
    {
        private readonly AppDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;

        public BlogController(AppDbContext context, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var posts = await _context.BlogPosts
                .Where(p => p.IsPublished)
                .OrderByDescending(p => p.CreatedAt)
                .ToListAsync();

            var latestPosts = await _context.FeaturedContents
                .Where(fc => fc.Section == "LatestPosts")
                .Include(fc => fc.BlogPost)
                .OrderBy(fc => fc.DisplayOrder)
                .Select(fc => fc.BlogPost)
                .ToListAsync();

            var recommendedPosts = await _context.FeaturedContents
                .Where(fc => fc.Section == "RecommendedPosts")
                .Include(fc => fc.BlogPost)
                .OrderBy(fc => fc.DisplayOrder)
                .Select(fc => fc.BlogPost)
                .ToListAsync();

            var popularPosts = await _context.FeaturedContents
                .Where(fc => fc.Section == "PopularPosts")
                .Include(fc => fc.BlogPost)
                .OrderBy(fc => fc.DisplayOrder)
                .Select(fc => fc.BlogPost)
                .ToListAsync();

            if (!latestPosts.Any())
            {
                latestPosts = await _context.BlogPosts
                    .Where(p => p.IsPublished)
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(3)
                    .ToListAsync();
            }

            if (!recommendedPosts.Any())
            {
                recommendedPosts = await _context.BlogPosts
                    .Where(p => p.IsPublished)
                    .OrderByDescending(p => p.ViewCount)
                    .Take(3)
                    .ToListAsync();
            }

            if (!popularPosts.Any())
            {
                popularPosts = await _context.BlogPosts
                    .Where(p => p.IsPublished)
                    .OrderByDescending(p => p.ViewCount)
                    .Take(10)
                    .ToListAsync();
            }

            ViewBag.PopularPosts = popularPosts;
            ViewBag.LatestPosts = latestPosts;
            ViewBag.RecommendedPosts = recommendedPosts;

            ViewData["MetaTitle"] = "Ilterisg Blog";
            ViewData["MetaDescription"] = "Is sagligi ve guvenligi hakkinda guncel yazilar.";
            ViewData["MetaKeywords"] = "isg, is guvenligi, blog, is sagligi";
            ViewData["CanonicalUrl"] = Url.Action(nameof(Index), "Blog", null, Request.Scheme);

            return View(posts);
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpGet]
        public async Task<IActionResult> Manage()
        {
            var posts = await _context.BlogPosts.ToListAsync();

            var blogPostsForViewBag = posts
                .Select(p => new
                {
                    Id = p.Id,
                    Title = p.Title
                })
                .ToList();

            var featuredContents = await _context.FeaturedContents
                .Include(fc => fc.BlogPost)
                .ToListAsync();

            ViewBag.BlogPosts = blogPostsForViewBag;
            ViewBag.FeaturedContents = featuredContents;
            return View(posts);
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpPost]
        public async Task<IActionResult> UpdateFeaturedContent([FromBody] UpdateFeaturedContentDto request)
        {
            try
            {
                if (request == null || string.IsNullOrEmpty(request.Section) || request.BlogPostId <= 0 || request.DisplayOrder <= 0)
                {
                    return Json(new { success = false, message = "Gecersiz parametreler." });
                }

                var blogPostExists = await _context.BlogPosts.AnyAsync(p => p.Id == request.BlogPostId);
                if (!blogPostExists)
                {
                    return Json(new { success = false, message = "Blog yazisi bulunamadi." });
                }

                var existingContent = await _context.FeaturedContents
                    .FirstOrDefaultAsync(fc => fc.Section == request.Section && fc.BlogPostId == request.BlogPostId);

                if (existingContent != null)
                {
                    existingContent.DisplayOrder = request.DisplayOrder;
                }
                else
                {
                    _context.FeaturedContents.Add(new FeaturedContent
                    {
                        Section = request.Section,
                        BlogPostId = request.BlogPostId,
                        DisplayOrder = request.DisplayOrder
                    });
                }

                await _context.SaveChangesAsync();
                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Guncelleme sirasinda hata olustu: " + ex.Message });
            }
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpPost]
        public async Task<IActionResult> RemoveFeaturedContent([FromBody] UpdateFeaturedContentDto request)
        {
            try
            {
                if (request == null || string.IsNullOrEmpty(request.Section) || request.BlogPostId <= 0)
                {
                    return Json(new { success = false, message = "Gecersiz parametreler." });
                }

                var content = await _context.FeaturedContents
                    .FirstOrDefaultAsync(fc => fc.Section == request.Section && fc.BlogPostId == request.BlogPostId);

                if (content == null)
                {
                    return Json(new { success = false, message = "One cikan icerik bulunamadi." });
                }

                _context.FeaturedContents.Remove(content);
                await _context.SaveChangesAsync();
                return Json(new { success = true });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = "Silme sirasinda hata olustu: " + ex.Message });
            }
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpGet]
        public IActionResult Create()
        {
            ViewData["MetaTitle"] = "Yeni Blog Yazisi";
            return View(new BlogPost());
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(BlogPost model)
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrWhiteSpace(userId))
            {
                return Forbid();
            }

            model.AuthorUserId = userId;
            model.CreatedAt = DateTime.UtcNow;

            ModelState.Remove(nameof(model.Author));
            ModelState.Remove(nameof(model.AuthorUserId));

            model.Content = SanitizeContent(model.Content);
            if (string.IsNullOrWhiteSpace(model.Summary))
            {
                var plain = HtmlToPlainText(model.Content);
                model.Summary = Truncate(plain, 150);
            }

            await ApplySeoDefaultsAsync(model, null);

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            _context.BlogPosts.Add(model);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Manage));
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpGet]
        public async Task<IActionResult> Edit(int id)
        {
            var post = await _context.BlogPosts.FindAsync(id);
            if (post == null)
            {
                return NotFound();
            }

            ViewData["MetaTitle"] = "Blog Yazisi Duzenle";
            return View(post);
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(
            int id,
            [Bind("Id,Title,Content,IsPublished,ImageUrl,Summary,MetaTitle,MetaDescription,MetaKeywords,Slug")] BlogPost model)
        {
            if (id != model.Id)
            {
                return BadRequest();
            }

            ModelState.Remove(nameof(model.AuthorUserId));
            ModelState.Remove(nameof(model.Author));

            model.Content = SanitizeContent(model.Content);
            if (string.IsNullOrWhiteSpace(model.Summary))
            {
                model.Summary = Truncate(HtmlToPlainText(model.Content), 150);
            }

            await ApplySeoDefaultsAsync(model, id);

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var post = await _context.BlogPosts.FindAsync(id);
            if (post == null)
            {
                return NotFound();
            }

            post.Title = model.Title;
            post.Content = model.Content;
            post.IsPublished = model.IsPublished;
            post.ImageUrl = model.ImageUrl;
            post.Summary = model.Summary;
            post.MetaTitle = model.MetaTitle;
            post.MetaDescription = model.MetaDescription;
            post.MetaKeywords = model.MetaKeywords;
            post.Slug = model.Slug;

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Manage));
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpPost]
        public async Task<IActionResult> UploadImage(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest("Dosya gecersiz.");
            }

            const string folderName = "Uploads";
            var webRoot = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
            var uploadsFolder = Path.Combine(webRoot, folderName);
            Directory.CreateDirectory(uploadsFolder);

            var ext = Path.GetExtension(file.FileName);
            var uniqueName = $"{Guid.NewGuid():N}{ext}";
            var filePath = Path.Combine(uploadsFolder, uniqueName);

            await using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await file.CopyToAsync(stream);
            }

            var imageUrl = Url.Content($"~/{folderName}/{uniqueName}");
            return Json(new { location = imageUrl });
        }

        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AddComment(int blogPostId, string authorName, string commentText)
        {
            var post = await _context.BlogPosts
                .Where(p => p.Id == blogPostId && p.IsPublished)
                .Select(p => new { p.Id, p.Slug })
                .FirstOrDefaultAsync();

            if (post == null)
            {
                return NotFound();
            }

            var normalizedAuthor = (authorName ?? string.Empty).Trim();
            var normalizedComment = (commentText ?? string.Empty).Trim();

            if (string.IsNullOrWhiteSpace(normalizedAuthor) || string.IsNullOrWhiteSpace(normalizedComment))
            {
                var invalidInputUrl = Url.RouteUrl("blog_details", new { id = post.Id, slug = post.Slug });
                return Redirect($"{invalidInputUrl}#comments");
            }

            if (normalizedAuthor.Length > 120)
            {
                normalizedAuthor = normalizedAuthor[..120];
            }

            if (normalizedComment.Length > 2000)
            {
                normalizedComment = normalizedComment[..2000];
            }

            _context.BlogComments.Add(new BlogComment
            {
                BlogPostId = post.Id,
                AuthorName = normalizedAuthor,
                CommentText = normalizedComment,
                CreatedAt = DateTime.UtcNow
            });

            await _context.SaveChangesAsync();

            var detailsUrl = Url.RouteUrl("blog_details", new { id = post.Id, slug = post.Slug });
            return Redirect($"{detailsUrl}#comments");
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Details(int id, string? slug = null)
        {
            var post = await _context.BlogPosts
                .Where(p => p.Id == id && p.IsPublished)
                .FirstOrDefaultAsync();

            if (post == null)
            {
                return NotFound();
            }

            if (!string.IsNullOrWhiteSpace(post.Slug) && !string.Equals(slug, post.Slug, StringComparison.OrdinalIgnoreCase))
            {
                return RedirectToRoutePermanent("blog_details", new { id = post.Id, slug = post.Slug });
            }

            post.ViewCount++;
            await _context.SaveChangesAsync();

            var latestPosts = await _context.FeaturedContents
                .Where(fc => fc.Section == "LatestPosts")
                .Include(fc => fc.BlogPost)
                .OrderBy(fc => fc.DisplayOrder)
                .Select(fc => fc.BlogPost)
                .ToListAsync();

            var recommendedPosts = await _context.FeaturedContents
                .Where(fc => fc.Section == "RecommendedPosts")
                .Include(fc => fc.BlogPost)
                .OrderBy(fc => fc.DisplayOrder)
                .Select(fc => fc.BlogPost)
                .ToListAsync();

            var popularPosts = await _context.FeaturedContents
                .Where(fc => fc.Section == "PopularPosts")
                .Include(fc => fc.BlogPost)
                .OrderBy(fc => fc.DisplayOrder)
                .Select(fc => fc.BlogPost)
                .ToListAsync();

            if (!latestPosts.Any())
            {
                latestPosts = await _context.BlogPosts
                    .Where(p => p.IsPublished && p.Id != id)
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(3)
                    .ToListAsync();
            }

            if (!recommendedPosts.Any())
            {
                recommendedPosts = await _context.BlogPosts
                    .Where(p => p.IsPublished && p.Id != id)
                    .OrderByDescending(p => p.ViewCount)
                    .Take(3)
                    .ToListAsync();
            }

            if (!popularPosts.Any())
            {
                popularPosts = await _context.BlogPosts
                    .Where(p => p.IsPublished)
                    .OrderByDescending(p => p.ViewCount)
                    .Take(10)
                    .ToListAsync();
            }

            ViewBag.LatestPosts = latestPosts;
            ViewBag.RecommendedPosts = recommendedPosts;
            ViewBag.PopularPosts = popularPosts;
            ViewBag.Comments = await _context.BlogComments
                .Where(c => c.BlogPostId == post.Id)
                .OrderByDescending(c => c.CreatedAt)
                .ToListAsync();

            ViewData["MetaTitle"] = string.IsNullOrWhiteSpace(post.MetaTitle) ? post.Title : post.MetaTitle;
            ViewData["MetaDescription"] = string.IsNullOrWhiteSpace(post.MetaDescription) ? post.Summary : post.MetaDescription;
            ViewData["MetaKeywords"] = string.IsNullOrWhiteSpace(post.MetaKeywords)
                ? BuildKeywords(post.Title, post.Summary ?? HtmlToPlainText(post.Content))
                : post.MetaKeywords;
            ViewData["CanonicalUrl"] = Url.RouteUrl("blog_details", new { id = post.Id, slug = post.Slug }, Request.Scheme);

            return View(post);
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpGet]
        public async Task<IActionResult> Delete(int id)
        {
            var post = await _context.BlogPosts.FindAsync(id);
            if (post == null)
            {
                return NotFound();
            }

            return View(post);
        }

        [Authorize(Roles = "Admin,Editor")]
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var post = await _context.BlogPosts.FindAsync(id);
            if (post != null)
            {
                _context.BlogPosts.Remove(post);
                await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Manage));
        }

        private static string SanitizeContent(string html)
        {
            var sanitizer = new HtmlSanitizer();
            sanitizer.AllowedTags.Add("iframe");
            sanitizer.AllowedTags.Add("img");
            sanitizer.AllowedAttributes.Add("src");
            sanitizer.AllowedAttributes.Add("width");
            sanitizer.AllowedAttributes.Add("height");
            sanitizer.AllowedAttributes.Add("frameborder");
            sanitizer.AllowedAttributes.Add("allowfullscreen");
            return sanitizer.Sanitize(html ?? string.Empty);
        }

        private async Task ApplySeoDefaultsAsync(BlogPost model, int? currentPostId)
        {
            var plainText = HtmlToPlainText(model.Content);

            if (string.IsNullOrWhiteSpace(model.MetaTitle))
            {
                model.MetaTitle = Truncate(model.Title, 70);
            }

            if (string.IsNullOrWhiteSpace(model.MetaDescription))
            {
                var source = string.IsNullOrWhiteSpace(model.Summary) ? plainText : model.Summary!;
                model.MetaDescription = Truncate(source, 160);
            }

            if (string.IsNullOrWhiteSpace(model.MetaKeywords))
            {
                model.MetaKeywords = BuildKeywords(model.Title, model.MetaDescription ?? plainText);
            }

            var baseSlug = BuildSlug(model.Title);
            model.Slug = await EnsureUniqueSlugAsync(baseSlug, currentPostId);
        }

        private async Task<string> EnsureUniqueSlugAsync(string baseSlug, int? currentPostId)
        {
            const int maxSlugLength = 220;
            var normalizedBase = string.IsNullOrWhiteSpace(baseSlug) ? "blog-yazisi" : baseSlug.Trim('-');
            if (normalizedBase.Length > maxSlugLength)
            {
                normalizedBase = normalizedBase[..maxSlugLength].Trim('-');
            }

            if (string.IsNullOrWhiteSpace(normalizedBase))
            {
                normalizedBase = "blog-yazisi";
            }

            var slug = normalizedBase;
            var suffix = 1;

            while (await _context.BlogPosts.AnyAsync(p =>
                       p.Slug == slug && (!currentPostId.HasValue || p.Id != currentPostId.Value)))
            {
                var suffixText = $"-{suffix++}";
                var maxBaseLength = Math.Max(1, maxSlugLength - suffixText.Length);
                var trimmedBase = normalizedBase.Length > maxBaseLength
                    ? normalizedBase[..maxBaseLength].Trim('-')
                    : normalizedBase;

                if (string.IsNullOrWhiteSpace(trimmedBase))
                {
                    trimmedBase = "blog-yazisi";
                }

                slug = $"{trimmedBase}{suffixText}";
            }

            return slug;
        }

        private static string HtmlToPlainText(string html)
        {
            if (string.IsNullOrWhiteSpace(html))
            {
                return string.Empty;
            }

            var noTags = Regex.Replace(html, "<.*?>", " ");
            var decoded = System.Net.WebUtility.HtmlDecode(noTags);
            return Regex.Replace(decoded, "\\s+", " ").Trim();
        }

        private static string Truncate(string? value, int maxLength)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            var text = value.Trim();
            return text.Length <= maxLength ? text : text[..maxLength].TrimEnd() + "...";
        }

        private static string BuildKeywords(string title, string text)
        {
            var combined = $"{title} {text}";
            var matches = Regex.Matches(combined, @"[a-zA-Z0-9çğıöşüÇĞİÖŞÜ]{3,}");
            var stopWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ve", "ile", "icin", "olarak", "gibi", "daha", "kadar", "blog", "yazi", "yazisi"
            };

            var keywords = matches
                .Select(m => NormalizeKeyword(m.Value))
                .Where(w => !string.IsNullOrWhiteSpace(w))
                .Where(w => !stopWords.Contains(w))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .ToList();

            if (!keywords.Any())
            {
                keywords.Add("isg");
            }

            return string.Join(", ", keywords);
        }

        private static string NormalizeKeyword(string value)
        {
            return value.Trim().ToLowerInvariant();
        }

        private static string BuildSlug(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "blog-yazisi";
            }

            var text = value.Trim().ToLowerInvariant();
            text = text
                .Replace('ç', 'c')
                .Replace('ğ', 'g')
                .Replace('ı', 'i')
                .Replace('ö', 'o')
                .Replace('ş', 's')
                .Replace('ü', 'u');

            text = text.Normalize(NormalizationForm.FormD);
            var normalized = new StringBuilder(text.Length);
            foreach (var c in text)
            {
                var category = CharUnicodeInfo.GetUnicodeCategory(c);
                if (category != UnicodeCategory.NonSpacingMark)
                {
                    normalized.Append(c);
                }
            }

            var ascii = normalized.ToString().Normalize(NormalizationForm.FormC);
            var slug = Regex.Replace(ascii, @"[^a-z0-9]+", "-");
            slug = Regex.Replace(slug, "-{2,}", "-").Trim('-');

            if (slug.Length > 220)
            {
                slug = slug[..220].Trim('-');
            }

            return string.IsNullOrWhiteSpace(slug) ? "blog-yazisi" : slug;
        }
    }
}
